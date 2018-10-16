/*
 * RTL8XXXU mac80211 USB driver
 *
 * Copyright (c) 2014 - 2017 Jes Sorensen <Jes.Sorensen@gmail.com>
 * Copyright (c) 2018 Vasily Khoruzhick <anarsoul@gmail.com>
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


u8 rtl8xxxu_usb_read8(struct rtl8xxxu_priv *priv, u16 addr)
{
  struct usb_device *udev = priv->udev;
  int len;
  u8 data;

  mutex_lock(&priv->usb_buf_mutex);
  len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			REALTEK_USB_CMD_REQ, REALTEK_USB_READ,
			addr, 0, &priv->usb_buf.val8, sizeof(u8),
			RTW_USB_CONTROL_MSG_TIMEOUT);
  data = priv->usb_buf.val8;
  mutex_unlock(&priv->usb_buf_mutex);

  if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_READ)
	dev_info(&udev->dev, "%s(%04x)   = 0x%02x, len %i\n",
	   __func__, addr, data, len);
  return data;
}

u16 rtl8xxxu_usb_read16(struct rtl8xxxu_priv *priv, u16 addr)
{
  struct usb_device *udev = priv->udev;
  int len;
  u16 data;

  mutex_lock(&priv->usb_buf_mutex);
  len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			REALTEK_USB_CMD_REQ, REALTEK_USB_READ,
			addr, 0, &priv->usb_buf.val16, sizeof(u16),
			RTW_USB_CONTROL_MSG_TIMEOUT);
  data = le16_to_cpu(priv->usb_buf.val16);
  mutex_unlock(&priv->usb_buf_mutex);

  if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_READ)
	dev_info(&udev->dev, "%s(%04x)  = 0x%04x, len %i\n",
	   __func__, addr, data, len);
  return data;
}

u32 rtl8xxxu_usb_read32(struct rtl8xxxu_priv *priv, u16 addr)
{
  struct usb_device *udev = priv->udev;
  int len;
  u32 data;

  mutex_lock(&priv->usb_buf_mutex);
  len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			REALTEK_USB_CMD_REQ, REALTEK_USB_READ,
			addr, 0, &priv->usb_buf.val32, sizeof(u32),
			RTW_USB_CONTROL_MSG_TIMEOUT);
  data = le32_to_cpu(priv->usb_buf.val32);
  mutex_unlock(&priv->usb_buf_mutex);

  if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_READ)
	dev_info(&udev->dev, "%s(%04x)  = 0x%08x, len %i\n",
	   __func__, addr, data, len);
  return data;
}

int rtl8xxxu_usb_write8(struct rtl8xxxu_priv *priv, u16 addr, u8 val)
{
  struct usb_device *udev = priv->udev;
  int ret;

  mutex_lock(&priv->usb_buf_mutex);
  priv->usb_buf.val8 = val;
  ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			REALTEK_USB_CMD_REQ, REALTEK_USB_WRITE,
			addr, 0, &priv->usb_buf.val8, sizeof(u8),
			RTW_USB_CONTROL_MSG_TIMEOUT);

  mutex_unlock(&priv->usb_buf_mutex);

  if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_WRITE)
	dev_info(&udev->dev, "%s(%04x) = 0x%02x\n",
	   __func__, addr, val);
  return ret;
}

int rtl8xxxu_usb_write16(struct rtl8xxxu_priv *priv, u16 addr, u16 val)
{
  struct usb_device *udev = priv->udev;
  int ret;

  mutex_lock(&priv->usb_buf_mutex);
  priv->usb_buf.val16 = cpu_to_le16(val);
  ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			REALTEK_USB_CMD_REQ, REALTEK_USB_WRITE,
			addr, 0, &priv->usb_buf.val16, sizeof(u16),
			RTW_USB_CONTROL_MSG_TIMEOUT);
  mutex_unlock(&priv->usb_buf_mutex);

  if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_WRITE)
	dev_info(&udev->dev, "%s(%04x) = 0x%04x\n",
	   __func__, addr, val);
  return ret;
}

int rtl8xxxu_usb_write32(struct rtl8xxxu_priv *priv, u16 addr, u32 val)
{
  struct usb_device *udev = priv->udev;
  int ret;

  mutex_lock(&priv->usb_buf_mutex);
  priv->usb_buf.val32 = cpu_to_le32(val);
  ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			REALTEK_USB_CMD_REQ, REALTEK_USB_WRITE,
			addr, 0, &priv->usb_buf.val32, sizeof(u32),
			RTW_USB_CONTROL_MSG_TIMEOUT);
  mutex_unlock(&priv->usb_buf_mutex);

  if (rtl8xxxu_debug & RTL8XXXU_DEBUG_REG_WRITE)
	dev_info(&udev->dev, "%s(%04x) = 0x%08x\n",
	   __func__, addr, val);
  return ret;
}

static int
rtl8xxxu_usb_writeN(struct rtl8xxxu_priv *priv, u16 addr, u8 *buf, u16 len)
{
  struct usb_device *udev = priv->udev;
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

static struct rtl8xxxu_intfops rtl8xxxu_usb_intfops = {
	.read8 = rtl8xxxu_usb_read8,
	.read16 = rtl8xxxu_usb_read16,
	.read32 = rtl8xxxu_usb_read32,
	.write8 = rtl8xxxu_usb_write8,
	.write16 = rtl8xxxu_usb_write16,
	.write32 = rtl8xxxu_usb_write32,
	.writeN = rtl8xxxu_usb_writeN,
};

static int rtl8xxxu_parse_usb(struct rtl8xxxu_priv *priv,
			      struct usb_interface *interface)
{
	struct usb_interface_descriptor *interface_desc;
	struct usb_host_interface *host_interface;
	struct usb_endpoint_descriptor *endpoint;
	struct device *dev = &priv->udev->dev;
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

			priv->pipe_in =	usb_rcvbulkpipe(priv->udev, num);
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

			priv->pipe_interrupt = usb_rcvintpipe(priv->udev, num);
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

static int rtl8xxxu_probe(struct usb_interface *interface,
			  const struct usb_device_id *id)
{
	struct rtl8xxxu_priv *priv;
	struct ieee80211_hw *hw;
	struct usb_device *udev;
	struct ieee80211_supported_band *sband;
	int ret;
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
	priv->udev = udev;
	priv->fops = (struct rtl8xxxu_fileops *)id->driver_info;
	priv->intfops = &rtl8xxxu_usb_intfops;
	mutex_init(&priv->usb_buf_mutex);
	mutex_init(&priv->h2c_mutex);
	INIT_LIST_HEAD(&priv->tx_urb_free_list);
	spin_lock_init(&priv->tx_urb_lock);
	INIT_LIST_HEAD(&priv->rx_urb_pending_list);
	spin_lock_init(&priv->rx_urb_lock);
	INIT_WORK(&priv->rx_urb_wq, rtl8xxxu_rx_urb_work);

	usb_set_intfdata(interface, hw);

	ret = rtl8xxxu_parse_usb(priv, interface);
	if (ret)
		goto exit;

	ret = rtl8xxxu_identify_chip(priv);
	if (ret) {
		dev_err(&udev->dev, "Fatal - failed to identify chip\n");
		goto exit;
	}

	ret = rtl8xxxu_read_efuse(priv);
	if (ret) {
		dev_err(&udev->dev, "Fatal - failed to read EFuse\n");
		goto exit;
	}

	ret = priv->fops->parse_efuse(priv);
	if (ret) {
		dev_err(&udev->dev, "Fatal - failed to parse EFuse\n");
		goto exit;
	}

	rtl8xxxu_print_chipinfo(priv);

	ret = priv->fops->load_firmware(priv);
	if (ret) {
		dev_err(&udev->dev, "Fatal - failed to load firmware\n");
		goto exit;
	}

	ret = rtl8xxxu_init_device(hw);
	if (ret)
		goto exit;

	hw->wiphy->max_scan_ssids = 1;
	hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;
	hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);
	hw->queues = 4;

	sband = &rtl8xxxu_supported_band;
	sband->ht_cap.ht_supported = true;
	sband->ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
	sband->ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_16;
	sband->ht_cap.cap = IEEE80211_HT_CAP_SGI_20 | IEEE80211_HT_CAP_SGI_40;
	memset(&sband->ht_cap.mcs, 0, sizeof(sband->ht_cap.mcs));
	sband->ht_cap.mcs.rx_mask[0] = 0xff;
	sband->ht_cap.mcs.rx_mask[4] = 0x01;
	if (priv->rf_paths > 1) {
		sband->ht_cap.mcs.rx_mask[1] = 0xff;
		sband->ht_cap.cap |= IEEE80211_HT_CAP_SGI_40;
	}
	sband->ht_cap.mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;
	/*
	 * Some APs will negotiate HT20_40 in a noisy environment leading
	 * to miserable performance. Rather than defaulting to this, only
	 * enable it if explicitly requested at module load time.
	 */
	if (rtl8xxxu_ht40_2g) {
		dev_info(&udev->dev, "Enabling HT_20_40 on the 2.4GHz band\n");
		sband->ht_cap.cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	}
	hw->wiphy->bands[NL80211_BAND_2GHZ] = sband;

	hw->wiphy->rts_threshold = 2347;

	SET_IEEE80211_DEV(priv->hw, &interface->dev);
	SET_IEEE80211_PERM_ADDR(hw, priv->mac_addr);

	hw->extra_tx_headroom = priv->fops->tx_desc_size;
	ieee80211_hw_set(hw, SIGNAL_DBM);
	/*
	 * The firmware handles rate control
	 */
	ieee80211_hw_set(hw, HAS_RATE_CONTROL);
	ieee80211_hw_set(hw, AMPDU_AGGREGATION);

	wiphy_ext_feature_set(hw->wiphy, NL80211_EXT_FEATURE_CQM_RSSI_LIST);

	ret = ieee80211_register_hw(priv->hw);
	if (ret) {
		dev_err(&udev->dev, "%s: Failed to register: %i\n",
			__func__, ret);
		goto exit;
	}

	return 0;

exit:
	usb_set_intfdata(interface, NULL);

	if (priv) {
		kfree(priv->fw_data);
		mutex_destroy(&priv->usb_buf_mutex);
		mutex_destroy(&priv->h2c_mutex);
	}
	usb_put_dev(udev);

	ieee80211_free_hw(hw);

	return ret;
}

static void rtl8xxxu_disconnect(struct usb_interface *interface)
{
	struct rtl8xxxu_priv *priv;
	struct ieee80211_hw *hw;

	hw = usb_get_intfdata(interface);
	priv = hw->priv;

	ieee80211_unregister_hw(hw);

	priv->fops->power_off(priv);

	usb_set_intfdata(interface, NULL);

	dev_info(&priv->udev->dev, "disconnecting\n");

	kfree(priv->fw_data);
	mutex_destroy(&priv->usb_buf_mutex);
	mutex_destroy(&priv->h2c_mutex);

	if (priv->udev->state != USB_STATE_NOTATTACHED) {
		dev_info(&priv->udev->dev,
			 "Device still attached, trying to reset\n");
		usb_reset_device(priv->udev);
	}
	usb_put_dev(priv->udev);
	ieee80211_free_hw(hw);
}

static const struct usb_device_id dev_table[] = {
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

static struct usb_driver rtl8xxxu_usb_driver = {
	.name = DRIVER_NAME,
	.probe = rtl8xxxu_probe,
	.disconnect = rtl8xxxu_disconnect,
	.id_table = dev_table,
	.no_dynamic_id = 1,
	.disable_hub_initiated_lpm = 1,
};

static int __init rtl8xxxu_usb_module_init(void)
{
	int res;

	res = usb_register(&rtl8xxxu_usb_driver);
	if (res < 0)
		pr_err(DRIVER_NAME ": usb_register() failed (%i)\n", res);

	return 0;
}

static void __exit rtl8xxxu_usb_module_exit(void)
{
	usb_deregister(&rtl8xxxu_usb_driver);
}

MODULE_DEVICE_TABLE(usb, dev_table);

module_init(rtl8xxxu_usb_module_init);
module_exit(rtl8xxxu_usb_module_exit);