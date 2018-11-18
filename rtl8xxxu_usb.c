/*
 * RTL8XXXU mac80211 USB driver
 *
 * Copyright (c) 2014 - 2017 Jes Sorensen <Jes.Sorensen@gmail.com>
 * Copyright (c) 2018 Vasily Khoruzhick <anarsoul@gmail.com>
 * Copyright (c) 2018 Marek Kraus <gamelaster@outlook.com>
 *
 * Portions, notably calibration code:
 * Copyright(c) 2007 - 2011 Realtek Corporation. All rights reserved.
 *
 * This driver was written as a replacement for the vendor provided
 * rtl8723au driver. As the Realtek 8xxx chips are very similar in
 * their programming interface, I have started adding support for
 * additional 8xxx chips like the 8192cu, 8188cus, etc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/usb.h>
#include <net/mac80211.h>
#include "rtl8xxxu.h"
#include "rtl8xxxu_regs.h"

#define USB_VENDOR_ID_REALTEK		0x0bda
#define RTL8XXXU_RX_URBS		32
#define RTL8XXXU_RX_URB_PENDING_WATER	8
#define RTL8XXXU_TX_URBS		64
#define RTL8XXXU_TX_URB_LOW_WATER	25
#define RTL8XXXU_TX_URB_HIGH_WATER	32
MODULE_FIRMWARE("rtlwifi/rtl8723aufw_A.bin");
MODULE_FIRMWARE("rtlwifi/rtl8723aufw_B.bin");
MODULE_FIRMWARE("rtlwifi/rtl8723aufw_B_NoBT.bin");
MODULE_FIRMWARE("rtlwifi/rtl8192cufw_A.bin");
MODULE_FIRMWARE("rtlwifi/rtl8192cufw_B.bin");
MODULE_FIRMWARE("rtlwifi/rtl8192cufw_TMSC.bin");
MODULE_FIRMWARE("rtlwifi/rtl8192eu_nic.bin");
MODULE_FIRMWARE("rtlwifi/rtl8723bu_nic.bin");
MODULE_FIRMWARE("rtlwifi/rtl8723bu_bt.bin");

static void rtl8xxxu_free_tx_resources(struct rtl8xxxu_usb_card *card)
{
	struct rtl8xxxu_tx_urb *tx_urb, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&card->tx_urb_lock, flags);
	list_for_each_entry_safe(tx_urb, tmp, &card->tx_urb_free_list, list) {
		list_del(&tx_urb->list);
		card->tx_urb_free_count--;
		usb_free_urb(&tx_urb->urb);
	}
	spin_unlock_irqrestore(&card->tx_urb_lock, flags);
}

static struct rtl8xxxu_tx_urb *
rtl8xxxu_alloc_tx_urb(struct rtl8xxxu_usb_card *card)
{
	struct rtl8xxxu_priv *priv = card->priv;
	struct rtl8xxxu_tx_urb *tx_urb;
	unsigned long flags;

	spin_lock_irqsave(&card->tx_urb_lock, flags);
	tx_urb = list_first_entry_or_null(&card->tx_urb_free_list,
					  struct rtl8xxxu_tx_urb, list);
	if (tx_urb) {
		list_del(&tx_urb->list);
		card->tx_urb_free_count--;
		if (card->tx_urb_free_count < RTL8XXXU_TX_URB_LOW_WATER &&
		    !priv->tx_stopped) {
			priv->tx_stopped = true;
			ieee80211_stop_queues(priv->hw);
		}
	}

	spin_unlock_irqrestore(&card->tx_urb_lock, flags);

	return tx_urb;
}

static void rtl8xxxu_free_tx_urb(struct rtl8xxxu_usb_card *card,
				 struct rtl8xxxu_tx_urb *tx_urb)
{
	struct rtl8xxxu_priv *priv = card->priv;
	unsigned long flags;

	INIT_LIST_HEAD(&tx_urb->list);

	spin_lock_irqsave(&card->tx_urb_lock, flags);

	list_add(&tx_urb->list, &card->tx_urb_free_list);
	card->tx_urb_free_count++;
	if (card->tx_urb_free_count > RTL8XXXU_TX_URB_HIGH_WATER &&
	    priv->tx_stopped) {
		priv->tx_stopped = false;
		ieee80211_wake_queues(priv->hw);
	}

	spin_unlock_irqrestore(&card->tx_urb_lock, flags);
}

static void rtl8xxxu_tx_complete(struct urb *urb)
{
	struct sk_buff *skb = (struct sk_buff *)urb->context;
	struct ieee80211_tx_info *tx_info;
	struct ieee80211_hw *hw;
	struct rtl8xxxu_priv *priv;
	struct rtl8xxxu_tx_urb *tx_urb =
		container_of(urb, struct rtl8xxxu_tx_urb, urb);

	tx_info = IEEE80211_SKB_CB(skb);
	
	hw = tx_info->rate_driver_data[0];
	priv = hw->priv;

	skb_pull(skb, priv->fops->tx_desc_size);

	ieee80211_tx_info_clear_status(tx_info);
	tx_info->status.rates[0].idx = -1;
	tx_info->status.rates[0].count = 0;

	if (!urb->status)
		tx_info->flags |= IEEE80211_TX_STAT_ACK;

	ieee80211_tx_status_irqsafe(hw, skb);

	rtl8xxxu_free_tx_urb(priv->card, tx_urb);
}

static void rtl8xxxu_free_rx_resources(struct rtl8xxxu_usb_card *card)
{
	struct rtl8xxxu_rx_urb *rx_urb, *tmp;
	unsigned long flags;
	
	spin_lock_irqsave(&card->rx_urb_lock, flags);

	list_for_each_entry_safe(rx_urb, tmp,
				 &card->rx_urb_pending_list, list) {
		list_del(&rx_urb->list);
		card->rx_urb_pending_count--;
		usb_free_urb(&rx_urb->urb);
	}

	spin_unlock_irqrestore(&card->rx_urb_lock, flags);
}

static void rtl8xxxu_queue_rx_urb(struct rtl8xxxu_usb_card *card,
				  struct rtl8xxxu_rx_urb *rx_urb)
{
	struct rtl8xxxu_priv *priv = card->priv;
	struct sk_buff *skb;
	unsigned long flags;
	int pending = 0;

	spin_lock_irqsave(&card->rx_urb_lock, flags);

	if (!priv->shutdown) {
		list_add_tail(&rx_urb->list, &card->rx_urb_pending_list);
		card->rx_urb_pending_count++;
		pending = card->rx_urb_pending_count;
	} else {
		skb = (struct sk_buff *)rx_urb->urb.context;
		dev_kfree_skb(skb);
		usb_free_urb(&rx_urb->urb);
	}

	spin_unlock_irqrestore(&card->rx_urb_lock, flags);

	if (pending > RTL8XXXU_RX_URB_PENDING_WATER)
		schedule_work(&card->rx_urb_wq);
}

static void rtl8xxxu_rx_complete(struct urb *urb)
{
	struct rtl8xxxu_rx_urb *rx_urb =
		container_of(urb, struct rtl8xxxu_rx_urb, urb);
	struct ieee80211_hw *hw = rx_urb->hw;
	struct rtl8xxxu_priv *priv = hw->priv;
	struct rtl8xxxu_usb_card *card = priv->card;
	struct sk_buff *skb = (struct sk_buff *)urb->context;
	struct device *dev = priv->dev;

	skb_put(skb, urb->actual_length);

	if (urb->status == 0) {
		priv->fops->parse_rx_desc(priv, skb);

		skb = NULL;
		rx_urb->urb.context = NULL;
		rtl8xxxu_queue_rx_urb(card, rx_urb);
	} else {
		dev_dbg(dev, "%s: status %i\n",	__func__, urb->status);
		goto cleanup;
	}
	return;

cleanup:
	usb_free_urb(urb);
	dev_kfree_skb(skb);
	return;
}

static int rtl8xxxu_submit_rx_urb(struct rtl8xxxu_usb_card *card,
				  struct rtl8xxxu_rx_urb *rx_urb)
{
	struct rtl8xxxu_priv *priv = card->priv;
	struct rtl8xxxu_fileops *fops = priv->fops;
	struct sk_buff *skb;
	int skb_size;
	int ret, rx_desc_sz;

	rx_desc_sz = fops->rx_desc_size;

	if (priv->rx_buf_aggregation && fops->rx_agg_buf_size) {
		skb_size = fops->rx_agg_buf_size;
		skb_size += (rx_desc_sz + sizeof(struct rtl8723au_phy_stats));
	} else {
		skb_size = IEEE80211_MAX_FRAME_LEN;
	}

	skb = __netdev_alloc_skb(NULL, skb_size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	memset(skb->data, 0, rx_desc_sz);
	usb_fill_bulk_urb(&rx_urb->urb, card->udev, priv->pipe_in, skb->data,
			  skb_size, rtl8xxxu_rx_complete, skb);
	usb_anchor_urb(&rx_urb->urb, &card->rx_anchor);
	ret = usb_submit_urb(&rx_urb->urb, GFP_ATOMIC);
	if (ret)
		usb_unanchor_urb(&rx_urb->urb);
	return ret;
}

static void rtl8xxxu_rx_urb_work(struct work_struct *work)
{
	struct rtl8xxxu_priv *priv;
	struct rtl8xxxu_usb_card *card;
	struct rtl8xxxu_rx_urb *rx_urb, *tmp;
	struct list_head local;
	struct sk_buff *skb;
	unsigned long flags;
	int ret;

	card = container_of(work, struct rtl8xxxu_usb_card, rx_urb_wq);
	INIT_LIST_HEAD(&local);
	priv = card->priv;

	spin_lock_irqsave(&card->rx_urb_lock, flags);

	list_splice_init(&card->rx_urb_pending_list, &local);
	card->rx_urb_pending_count = 0;

	spin_unlock_irqrestore(&card->rx_urb_lock, flags);

	list_for_each_entry_safe(rx_urb, tmp, &local, list) {
		list_del_init(&rx_urb->list);
		ret = rtl8xxxu_submit_rx_urb(card, rx_urb);
		/*
		 * If out of memory or temporary error, put it back on the
		 * queue and try again. Otherwise the device is dead/gone
		 * and we should drop it.
		 */
		switch (ret) {
		case 0:
			break;
		case -ENOMEM:
		case -EAGAIN:
			rtl8xxxu_queue_rx_urb(card, rx_urb);
			break;
		default:
			pr_info("failed to requeue urb %i\n", ret);
			skb = (struct sk_buff *)rx_urb->urb.context;
			dev_kfree_skb(skb);
			usb_free_urb(&rx_urb->urb);
		}
	}
}

static void rtl8xxxu_int_complete(struct urb *urb)
{
	struct rtl8xxxu_priv *priv = (struct rtl8xxxu_priv *)urb->context;
	struct rtl8xxxu_usb_card *card = priv->card;
	struct device *dev = priv->dev;
	int ret;

	if (rtl8xxxu_debug & RTL8XXXU_DEBUG_INTERRUPT)
		dev_dbg(dev, "%s: status %i\n", __func__, urb->status);
	if (urb->status == 0) {
		usb_anchor_urb(urb, &card->int_anchor);
		ret = usb_submit_urb(urb, GFP_ATOMIC);
		if (ret)
			usb_unanchor_urb(urb);
	} else {
		dev_dbg(dev, "%s: Error %i\n", __func__, urb->status);
	}
}


static int rtl8xxxu_submit_int_urb(struct ieee80211_hw *hw)
{
	struct rtl8xxxu_priv *priv = hw->priv;
	struct rtl8xxxu_usb_card *card = priv->card;
	struct urb *urb;
	u32 val32;
	int ret;

	urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!urb)
		return -ENOMEM;

	usb_fill_int_urb(urb, card->udev, priv->pipe_interrupt,
			 priv->int_buf, USB_INTR_CONTENT_LENGTH,
			 rtl8xxxu_int_complete, priv, 1);
	usb_anchor_urb(urb, &card->int_anchor);
	ret = usb_submit_urb(urb, GFP_KERNEL);
	if (ret) {
		usb_unanchor_urb(urb);
		goto error;
	}

	val32 = priv->iops->read32(priv, REG_USB_HIMR);
	val32 |= USB_HIMR_CPWM;
	priv->iops->write32(priv, REG_USB_HIMR, val32);

error:
	return ret;
}

static int rtl8xxxu_parse_usb(struct rtl8xxxu_usb_card *card,
			      struct usb_interface *interface)
{
	struct rtl8xxxu_priv *priv = card->priv;
	struct usb_interface_descriptor *interface_desc;
	struct usb_host_interface *host_interface;
	struct usb_endpoint_descriptor *endpoint;
	struct device *dev = priv->dev;
	int i, j = 0, endpoints;
	u8 dir, xtype, num;
	int ret = 0;
	
	host_interface = &interface->altsetting[0];
	interface_desc = &host_interface->desc;
	endpoints = interface_desc->bNumEndpoints;
	
	for (i = 0; i < endpoints; i++) {
		endpoint = &host_interface->endpoint[i].desc;

		dir = endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK;
		num = usb_endpoint_num(endpoint);
		xtype = usb_endpoint_type(endpoint);
		if (rtl8xxxu_debug & RTL8XXXU_DEBUG_USB)
			dev_dbg(dev,
				"%s: endpoint: dir %02x, # %02x, type %02x\n",
				__func__, dir, num, xtype);
		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			if (rtl8xxxu_debug & RTL8XXXU_DEBUG_USB)
				dev_dbg(dev, "%s: in endpoint num %i\n",
					__func__, num);

			if (priv->pipe_in) {
				dev_warn(dev,
					 "%s: Too many IN pipes\n", __func__);
				ret = -EINVAL;
				goto exit;
			}

			priv->pipe_in =	usb_rcvbulkpipe(card->udev, num);
		}

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_int(endpoint)) {
			if (rtl8xxxu_debug & RTL8XXXU_DEBUG_USB)
				dev_dbg(dev, "%s: interrupt endpoint num %i\n",
					__func__, num);

			if (priv->pipe_interrupt) {
				dev_warn(dev, "%s: Too many INTERRUPT pipes\n",
					 __func__);
				ret = -EINVAL;
				goto exit;
			}

			priv->pipe_interrupt = usb_rcvintpipe(card->udev, num);
		}

		if (usb_endpoint_dir_out(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			if (rtl8xxxu_debug & RTL8XXXU_DEBUG_USB)
				dev_dbg(dev, "%s: out endpoint num %i\n",
					__func__, num);
			if (j >= RTL8XXXU_OUT_ENDPOINTS) {
				dev_warn(dev,
					 "%s: Too many OUT pipes\n", __func__);
				ret = -EINVAL;
				goto exit;
			}
			priv->out_ep[j++] = num;
		}
	}
exit:
	priv->nr_out_eps = j;
	return ret;
}

static int rtl8xxxu_usb_probe(struct usb_interface *interface,
			  const struct usb_device_id *id)
{
	struct rtl8xxxu_usb_card *card;
	struct rtl8xxxu_priv *priv;
	struct ieee80211_hw *hw;
	struct usb_device *udev;
	int ret = 0;
	int untested = 1;
	
	udev = usb_get_dev(interface_to_usbdev(interface));

	switch (id->idVendor) {
	case USB_VENDOR_ID_REALTEK:
		switch(id->idProduct) {
		case 0x1724:
		case 0x8176:
		case 0x8178:
		case 0x817f:
		case 0x818b:
			untested = 0;
			break;
		}
		break;
	case 0x7392:
		if (id->idProduct == 0x7811)
			untested = 0;
		break;
	case 0x050d:
		if (id->idProduct == 0x1004)
			untested = 0;
		break;
	case 0x20f4:
		if (id->idProduct == 0x648b)
			untested = 0;
		break;
	case 0x2001:
		if (id->idProduct == 0x3308)
			untested = 0;
		break;
	case 0x2357:
		if (id->idProduct == 0x0109)
			untested = 0;
		break;
	default:
		break;
	}

	if (untested) {
		rtl8xxxu_debug |= RTL8XXXU_DEBUG_EFUSE;
		dev_info(&udev->dev,
			 "This Realtek USB WiFi dongle (0x%04x:0x%04x) is untested!\n",
			 id->idVendor, id->idProduct);
		dev_info(&udev->dev,
			 "Please report results to Jes.Sorensen@gmail.com\n");
	}

	
	hw = ieee80211_alloc_hw(sizeof(struct rtl8xxxu_priv), &rtl8xxxu_ops);
	if (!hw) {
		ret = -ENOMEM;
		priv = NULL;
		goto exit;
	}

	priv = hw->priv;
	priv->hw = hw;
	priv->dev = &udev->dev;
	priv->fops = (struct rtl8xxxu_fileops *)id->driver_info;
	priv->iops = &rtl8xxxu_usb_intops;

	
	card = kzalloc(sizeof(struct rtl8xxxu_usb_card), GFP_KERNEL);
	if (!card)
		goto exit;
	
	card->priv = priv;
	card->udev = udev;
	priv->card = card;
	
	mutex_init(&card->usb_buf_mutex);
	mutex_init(&priv->h2c_mutex);
	INIT_LIST_HEAD(&card->tx_urb_free_list);
	spin_lock_init(&card->tx_urb_lock);
	INIT_LIST_HEAD(&card->rx_urb_pending_list);
	spin_lock_init(&card->rx_urb_lock);
	INIT_WORK(&card->rx_urb_wq, rtl8xxxu_rx_urb_work);

	usb_set_intfdata(interface, hw);

	ret = rtl8xxxu_parse_usb(card, interface);
	if (ret)
		goto exit;
	
	ret = rtl8xxxu_hw_init(priv);
	if (ret)
		goto exit;
	
	return 0;

exit:
	usb_set_intfdata(interface, NULL);

	if (priv) {
		kfree(priv->fw_data);
		mutex_destroy(&card->usb_buf_mutex);
		mutex_destroy(&priv->h2c_mutex);
	}
	usb_put_dev(udev);

	ieee80211_free_hw(priv->hw);
	
	if (card) {
		kzfree(card);
	}

	return ret;
}

static u8 rtl8xxxu_usb_read8(struct rtl8xxxu_priv *priv, u16 addr)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	struct usb_device *udev = card->udev;
	int len;
	u8 data;

	mutex_lock(&card->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      REALTEK_USB_CMD_REQ, REALTEK_USB_READ,
			      addr, 0, &card->usb_buf.val8, sizeof(u8),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = card->usb_buf.val8;
	mutex_unlock(&card->usb_buf_mutex);

	if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_READ)
		dev_info(&udev->dev, "%s(%04x)   = 0x%02x, len %i\n",
			 __func__, addr, data, len);
	return data;
}

static u16 rtl8xxxu_usb_read16(struct rtl8xxxu_priv *priv, u16 addr)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	struct usb_device *udev = card->udev;
	int len;
	u16 data;

	mutex_lock(&card->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      REALTEK_USB_CMD_REQ, REALTEK_USB_READ,
			      addr, 0, &card->usb_buf.val16, sizeof(u16),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le16_to_cpu(card->usb_buf.val16);
	mutex_unlock(&card->usb_buf_mutex);

	if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_READ)
		dev_info(&udev->dev, "%s(%04x)  = 0x%04x, len %i\n",
			 __func__, addr, data, len);
	return data;
}

static u32 rtl8xxxu_usb_read32(struct rtl8xxxu_priv *priv, u16 addr)
{
	struct rtl8xxxu_usb_card *card = (struct rtl8xxxu_usb_card *) priv->card;
	struct usb_device *udev = card->udev;
	int len;
	u32 data;
	

	mutex_lock(&card->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      REALTEK_USB_CMD_REQ, REALTEK_USB_READ,
			      addr, 0, &card->usb_buf.val32, sizeof(u32),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le32_to_cpu(card->usb_buf.val32);
	mutex_unlock(&card->usb_buf_mutex);

	if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_READ)
		dev_info(&udev->dev, "%s(%04x)  = 0x%08x, len %i\n",
			 __func__, addr, data, len);
	return data;
}

static int rtl8xxxu_usb_write8(struct rtl8xxxu_priv *priv, u16 addr, u8 val)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	struct usb_device *udev = card->udev;
	int ret;

	mutex_lock(&card->usb_buf_mutex);
	card->usb_buf.val8 = val;
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      REALTEK_USB_CMD_REQ, REALTEK_USB_WRITE,
			      addr, 0, &card->usb_buf.val8, sizeof(u8),
			      RTW_USB_CONTROL_MSG_TIMEOUT);

	mutex_unlock(&card->usb_buf_mutex);

	if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_WRITE)
		dev_info(&udev->dev, "%s(%04x) = 0x%02x\n",
			 __func__, addr, val);
	return ret;
}

static int rtl8xxxu_usb_write16(struct rtl8xxxu_priv *priv, u16 addr, u16 val)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	struct usb_device *udev = card->udev;
	int ret;

	mutex_lock(&card->usb_buf_mutex);
	card->usb_buf.val16 = cpu_to_le16(val);
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      REALTEK_USB_CMD_REQ, REALTEK_USB_WRITE,
			      addr, 0, &card->usb_buf.val16, sizeof(u16),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	mutex_unlock(&card->usb_buf_mutex);

	if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_WRITE)
		dev_info(&udev->dev, "%s(%04x) = 0x%04x\n",
			 __func__, addr, val);
	return ret;
}

static int rtl8xxxu_usb_write32(struct rtl8xxxu_priv *priv, u16 addr, u32 val)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	struct usb_device *udev = card->udev;
	int ret;

	mutex_lock(&card->usb_buf_mutex);
	card->usb_buf.val32 = cpu_to_le32(val);
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      REALTEK_USB_CMD_REQ, REALTEK_USB_WRITE,
			      addr, 0, &card->usb_buf.val32, sizeof(u32),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	mutex_unlock(&card->usb_buf_mutex);

	if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_WRITE)
		dev_info(&udev->dev, "%s(%04x) = 0x%08x\n",
			 __func__, addr, val);
	return ret;
}

static int
rtl8xxxu_usb_writeN(struct rtl8xxxu_priv *priv, u16 addr, u8 *buf, u16 len)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	struct usb_device *udev = card->udev;
	int blocksize = priv->fops->writeN_block_size;
	int ret, i, count, remainder;

	count = len / blocksize;
	remainder = len % blocksize;

	for (i = 0; i < count; i++) {
		ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				      REALTEK_USB_CMD_REQ, REALTEK_USB_WRITE,
				      addr, 0, buf, blocksize,
				      RTW_USB_CONTROL_MSG_TIMEOUT);
		if (ret != blocksize)
			goto write_error;

		addr += blocksize;
		buf += blocksize;
	}

	if (remainder) {
		ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				      REALTEK_USB_CMD_REQ, REALTEK_USB_WRITE,
				      addr, 0, buf, remainder,
				      RTW_USB_CONTROL_MSG_TIMEOUT);
		if (ret != remainder)
			goto write_error;
	}

	return len;

write_error:
	dev_info(&udev->dev,
		 "%s: Failed to write block at addr: %04x size: %04x\n",
		 __func__, addr, blocksize);
	return -EAGAIN;
}

static void rtl8xxxu_usb_configure_beacon_queue(struct rtl8xxxu_priv *priv, struct rtl8xxxu_queues queues)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	priv->pipe_out[TXDESC_QUEUE_VO] =
		usb_sndbulkpipe(card->udev, priv->out_ep[queues.vop]);
	priv->pipe_out[TXDESC_QUEUE_VI] =
		usb_sndbulkpipe(card->udev, priv->out_ep[queues.vip]);
	priv->pipe_out[TXDESC_QUEUE_BE] =
		usb_sndbulkpipe(card->udev, priv->out_ep[queues.bep]);
	priv->pipe_out[TXDESC_QUEUE_BK] =
		usb_sndbulkpipe(card->udev, priv->out_ep[queues.bkp]);
	priv->pipe_out[TXDESC_QUEUE_BEACON] =
		usb_sndbulkpipe(card->udev, priv->out_ep[0]);
	priv->pipe_out[TXDESC_QUEUE_MGNT] =
		usb_sndbulkpipe(card->udev, priv->out_ep[queues.mgp]);
	priv->pipe_out[TXDESC_QUEUE_HIGH] =
		usb_sndbulkpipe(card->udev, priv->out_ep[queues.hip]);
	priv->pipe_out[TXDESC_QUEUE_CMD] =
		usb_sndbulkpipe(card->udev, priv->out_ep[0]);
}

static int rtl8xxxu_usb_tx(struct rtl8xxxu_priv *priv, struct sk_buff *skb, u32 queue)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	struct device *dev = priv->dev;
	struct rtl8xxxu_tx_urb *tx_urb;
	int ret;
	
	tx_urb = rtl8xxxu_alloc_tx_urb(card);
	if (!tx_urb) {
		dev_warn(dev, "%s: Unable to allocate tx urb\n", __func__);
		return 1;
	}

	usb_fill_bulk_urb(&tx_urb->urb, card->udev, priv->pipe_out[queue],
			  skb->data, skb->len, rtl8xxxu_tx_complete, skb);

	usb_anchor_urb(&tx_urb->urb, &card->tx_anchor);
	ret = usb_submit_urb(&tx_urb->urb, GFP_ATOMIC);
	if (ret) {
		usb_unanchor_urb(&tx_urb->urb);
		rtl8xxxu_free_tx_urb(card, tx_urb);
		return 1;
	}

	return 0;
}

static int rtl8xxxu_usb_identify_chip(struct rtl8xxxu_priv *priv, u32 chip_cfg)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	u32 bonding;
	
	if (chip_cfg & SYS_CFG_BT_FUNC) {
		if (priv->chip_cut >= 3) {
			sprintf(priv->chip_name, "8723BU");
			priv->rtl_chip = RTL8723B;
		} else {
			sprintf(priv->chip_name, "8723AU");
			card->usb_interrupts = 1;
			priv->rtl_chip = RTL8723A;
		}

		priv->rf_paths = 1;
		priv->rx_paths = 1;
		priv->tx_paths = 1;

		chip_cfg = priv->iops->read32(priv, REG_MULTI_FUNC_CTRL);
		if (chip_cfg & MULTI_WIFI_FUNC_EN)
			priv->has_wifi = 1;
		if (chip_cfg & MULTI_BT_FUNC_EN)
			priv->has_bluetooth = 1;
		if (chip_cfg & MULTI_GPS_FUNC_EN)
			priv->has_gps = 1;
		priv->is_multi_func = 1;
	} else if (chip_cfg & SYS_CFG_TYPE_ID) {
		bonding = priv->iops->read32(priv, REG_HPON_FSM);
		bonding &= HPON_FSM_BONDING_MASK;
		if (priv->fops->tx_desc_size ==
		    sizeof(struct rtl8xxxu_txdesc40)) {
			if (bonding == HPON_FSM_BONDING_1T2R) {
				sprintf(priv->chip_name, "8191EU");
				priv->rf_paths = 2;
				priv->rx_paths = 2;
				priv->tx_paths = 1;
				priv->rtl_chip = RTL8191E;
			} else {
				sprintf(priv->chip_name, "8192EU");
				priv->rf_paths = 2;
				priv->rx_paths = 2;
				priv->tx_paths = 2;
				priv->rtl_chip = RTL8192E;
			}
		} else if (bonding == HPON_FSM_BONDING_1T2R) {
			sprintf(priv->chip_name, "8191CU");
			priv->rf_paths = 2;
			priv->rx_paths = 2;
			priv->tx_paths = 1;
			card->usb_interrupts = 1;
			priv->rtl_chip = RTL8191C;
		} else {
			sprintf(priv->chip_name, "8192CU");
			priv->rf_paths = 2;
			priv->rx_paths = 2;
			priv->tx_paths = 2;
			card->usb_interrupts = 1;
			priv->rtl_chip = RTL8192C;
		}
		priv->has_wifi = 1;
	} else {
		sprintf(priv->chip_name, "8188CU");
		priv->rf_paths = 1;
		priv->rx_paths = 1;
		priv->tx_paths = 1;
		priv->rtl_chip = RTL8188C;
		card->usb_interrupts = 1;
		priv->has_wifi = 1;
	}
	
	return 0;
}

static int rtl8xxxu_usb_start(struct rtl8xxxu_priv *priv, int *ret) // TODO: Review this ret handling
{
	struct rtl8xxxu_usb_card *card = priv->card;
	struct ieee80211_hw *hw = priv->hw;
	struct rtl8xxxu_rx_urb *rx_urb;
	struct rtl8xxxu_tx_urb *tx_urb;
	unsigned long flags;
	int i;

	init_usb_anchor(&card->rx_anchor);
	init_usb_anchor(&card->tx_anchor);
	init_usb_anchor(&card->int_anchor);

	if (card->usb_interrupts) {
		*ret = rtl8xxxu_submit_int_urb(hw);
		if (*ret)
			return 1;
	}

	for (i = 0; i < RTL8XXXU_TX_URBS; i++) {
		tx_urb = kmalloc(sizeof(struct rtl8xxxu_tx_urb), GFP_KERNEL);
		if (!tx_urb) {
			if (!i)
				*ret = -ENOMEM;

			rtl8xxxu_free_tx_resources(card);
			return 2;
		}
		usb_init_urb(&tx_urb->urb);
		INIT_LIST_HEAD(&tx_urb->list);
		tx_urb->hw = hw;
		list_add(&tx_urb->list, &card->tx_urb_free_list);
		card->tx_urb_free_count++;
	}

	priv->tx_stopped = false;

	spin_lock_irqsave(&card->rx_urb_lock, flags);
	priv->shutdown = false;
	spin_unlock_irqrestore(&card->rx_urb_lock, flags);

	for (i = 0; i < RTL8XXXU_RX_URBS; i++) {
		rx_urb = kmalloc(sizeof(struct rtl8xxxu_rx_urb), GFP_KERNEL);
		if (!rx_urb) {
			if (!i)
				*ret = -ENOMEM;

			rtl8xxxu_free_tx_resources(card);
			return 2;
		}
		usb_init_urb(&rx_urb->urb);
		INIT_LIST_HEAD(&rx_urb->list);
		rx_urb->hw = hw;

		*ret = rtl8xxxu_submit_rx_urb(card, rx_urb);
	}

	return 0;
}

static void rtl8xxxu_usb_stop(struct rtl8xxxu_priv *priv)
{
	struct rtl8xxxu_usb_card *card = priv->card;
	unsigned long flags;

	spin_lock_irqsave(&card->rx_urb_lock, flags);
	priv->shutdown = true;
	spin_unlock_irqrestore(&card->rx_urb_lock, flags);

	usb_kill_anchored_urbs(&card->rx_anchor);
	usb_kill_anchored_urbs(&card->tx_anchor);
	if (card->usb_interrupts)
		usb_kill_anchored_urbs(&card->int_anchor);

	priv->iops->write8(priv, REG_TXPAUSE, 0xff);

	priv->fops->disable_rf(priv);

	/*
	 * Disable interrupts
	 */
	if (card->usb_interrupts)
		priv->iops->write32(priv, REG_USB_HIMR, 0);

	rtl8xxxu_free_rx_resources(card);
	rtl8xxxu_free_tx_resources(card);
}

static void rtl8xxxu_usb_disconnect(struct usb_interface *interface)
{
	struct rtl8xxxu_priv *priv;
	struct rtl8xxxu_usb_card *card;
	struct ieee80211_hw *hw;

	hw = usb_get_intfdata(interface);
	priv = hw->priv;
	card = priv->card;

	ieee80211_unregister_hw(hw);

	priv->fops->power_off(priv);

	usb_set_intfdata(interface, NULL);

	dev_info(priv->dev, "disconnecting\n");

	kfree(priv->fw_data);
	mutex_destroy(&card->usb_buf_mutex);
	mutex_destroy(&priv->h2c_mutex);

	if (card->udev->state != USB_STATE_NOTATTACHED) {
		dev_info(priv->dev,
			 "Device still attached, trying to reset\n");
		usb_reset_device(card->udev);
	}
	usb_put_dev(card->udev);
	ieee80211_free_hw(hw);
	kzfree(card);
}

static const struct usb_device_id rtl8xxxu_usb_dev_table[] = {
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x8724, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8723au_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x1724, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8723au_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x0724, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8723au_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x818b, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192eu_fops},
/* TP-Link TL-WN822N v4 */
{USB_DEVICE_AND_INTERFACE_INFO(0x2357, 0x0108, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192eu_fops},
/* D-Link DWA-131 rev E1, tested by David Patiño */
{USB_DEVICE_AND_INTERFACE_INFO(0x2001, 0x3319, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192eu_fops},
/* Tested by Myckel Habets */
{USB_DEVICE_AND_INTERFACE_INFO(0x2357, 0x0109, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192eu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0xb720, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8723bu_fops},
#ifdef CONFIG_RTL8XXXU_UNTESTED
/* Still supported by rtlwifi */
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x8176, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x8178, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x817f, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
/* Tested by Larry Finger */
{USB_DEVICE_AND_INTERFACE_INFO(0x7392, 0x7811, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
/* Tested by Andrea Merello */
{USB_DEVICE_AND_INTERFACE_INFO(0x050d, 0x1004, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
/* Tested by Jocelyn Mayer */
{USB_DEVICE_AND_INTERFACE_INFO(0x20f4, 0x648b, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
/* Tested by Stefano Bravi */
{USB_DEVICE_AND_INTERFACE_INFO(0x2001, 0x3308, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
/* Tested by Marek Kraus - Edimax EW-7611ULB */
{USB_DEVICE_AND_INTERFACE_INFO(0x7392, 0xa611, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8723bu_fops},
/* Currently untested 8188 series devices */
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x018a, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x8191, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x8170, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x8177, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x817a, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x817b, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x817d, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x817e, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x818a, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x317f, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x1058, 0x0631, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x04bb, 0x094c, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x050d, 0x1102, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x06f8, 0xe033, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x07b8, 0x8189, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0846, 0x9041, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0b05, 0x17ba, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x1e1e, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x5088, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0df6, 0x0052, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0df6, 0x005c, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0eb0, 0x9071, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x103c, 0x1629, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x13d3, 0x3357, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2001, 0x330b, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2019, 0x4902, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2019, 0xab2a, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2019, 0xab2e, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2019, 0xed17, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x4855, 0x0090, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x4856, 0x0091, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0xcdab, 0x8010, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x04f2, 0xaff7, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x04f2, 0xaff9, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x04f2, 0xaffa, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x04f2, 0xaff8, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x04f2, 0xaffb, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x04f2, 0xaffc, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2019, 0x1201, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
/* Currently untested 8192 series devices */
{USB_DEVICE_AND_INTERFACE_INFO(0x04bb, 0x0950, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x050d, 0x2102, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x050d, 0x2103, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0586, 0x341f, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x06f8, 0xe035, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0b05, 0x17ab, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0df6, 0x0061, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0df6, 0x0070, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0789, 0x016d, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x07aa, 0x0056, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x07b8, 0x8178, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0846, 0x9021, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0846, 0xf001, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x2e2e, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0e66, 0x0019, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x0e66, 0x0020, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2001, 0x3307, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2001, 0x3309, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2001, 0x330a, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2019, 0xab2b, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x20f4, 0x624d, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2357, 0x0100, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x4855, 0x0091, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x7392, 0x7822, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192cu_fops},
/* found in rtl8192eu vendor driver */
{USB_DEVICE_AND_INTERFACE_INFO(0x2357, 0x0107, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192eu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(0x2019, 0xab33, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192eu_fops},
{USB_DEVICE_AND_INTERFACE_INFO(USB_VENDOR_ID_REALTEK, 0x818c, 0xff, 0xff, 0xff),
	.driver_info = (unsigned long)&rtl8192eu_fops},
#endif
{ }
};

MODULE_DEVICE_TABLE(usb, rtl8xxxu_usb_dev_table);

static struct usb_driver rtl8xxxu_usb_driver = {
	.name = DRIVER_NAME,
	.probe = rtl8xxxu_usb_probe,
	.disconnect = rtl8xxxu_usb_disconnect,
	.id_table = rtl8xxxu_usb_dev_table,
	.no_dynamic_id = 1,
	.disable_hub_initiated_lpm = 1,
};

int rtl8xxxu_usb_register(void)
{
	return usb_register(&rtl8xxxu_usb_driver);
}

void rtl8xxxu_usb_deregister(void)
{
	usb_deregister(&rtl8xxxu_usb_driver);
}

struct rtl8xxxu_intops rtl8xxxu_usb_intops = {
	.read8 = rtl8xxxu_usb_read8,
	.read16 = rtl8xxxu_usb_read16,
	.read32 = rtl8xxxu_usb_read32,
	.write8 = rtl8xxxu_usb_write8,
	.write16 = rtl8xxxu_usb_write16,
	.write32 = rtl8xxxu_usb_write32,
	.writeN = rtl8xxxu_usb_writeN,
	.configure_beacon_queue = rtl8xxxu_usb_configure_beacon_queue,
	.tx = rtl8xxxu_usb_tx,
	.identify_chip = rtl8xxxu_usb_identify_chip,
	.start = rtl8xxxu_usb_start,
	.stop = rtl8xxxu_usb_stop
};
