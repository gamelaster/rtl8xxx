// SPDX-License-Identifier: GPL-2.0-only
/*
 * RTL8XXXU mac80211 USB driver
 *
 * Copyright (c) 2014 - 2017 Jes Sorensen <Jes.Sorensen@gmail.com>
 * Copyright (c) 2018 Vasily Khoruzhick <anarsoul@gmail.com>
 * Copyright (c) 2018 - 2019 Marek Kraus <gamelaster@outlook.com>
 *
 * Portions, notably calibration code:
 * Copyright(c) 2007 - 2011 Realtek Corporation. All rights reserved.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/mac80211.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/usb.h>
#include "rtl8xxxu.h"
#include "rtl8xxxu_regs.h"

#define SDIO_VENDOR_ID_REALTEK 0x024c
MODULE_FIRMWARE("rtlwifi/rtl8723bs_nic.bin");
MODULE_FIRMWARE("rtlwifi/rtl8723bs_bt.bin");

static bool rtl8xxxu_sdio_claim_host_needed(struct sdio_func *func)
{
	// TODO:
	return false;
}

/*static u8 rtl8xxxu_sdio_read8(struct rtl8xxxu_priv *priv, u16 addr)
{
	struct rtl8xxxu_sdio_card *card = priv->card;
	struct sdio_func *func = card->func;
	int err;
	bool claim_needed;
	u8 data;
	
	claim_needed = rtl8xxxu_sdio_claim_host_needed(func);

	if (claim_needed)
		sdio_claim_host(func);
	data = sdio_readb(func, addr, &err);
	if (claim_needed)
		sdio_release_host(func);
	if (err)
		dev_dbg(priv->dev, "%s: FAIL!(%d) addr = 0x%05x\n", __func__, err, addr);
	return data;
}

static u16 rtl8xxxu_sdio_read16(struct rtl8xxxu_priv *priv, u16 addr)
{
	struct rtl8xxxu_sdio_card *card = priv->card;
	struct sdio_func *func = card->func;
	int err;
	bool claim_needed;
	u16 data;
	
	claim_needed = rtl8xxxu_sdio_claim_host_needed(func);

	if (claim_needed)
		sdio_claim_host(func);
	data = sdio_readw(func, addr, &err);
	if (claim_needed)
		sdio_release_host(func);
	if (err)
		dev_dbg(priv->dev, "%s: FAIL!(%d) addr = 0x%05x\n", __func__, err, addr);
	return data;
}*/

static u32 rtl8xxxu_sdio_read32(struct rtl8xxxu_priv *priv, u16 addr)
{
	struct rtl8xxxu_sdio_card *card = priv->card;
	struct sdio_func *func = card->func;
	int err;
	bool claim_needed;
	u32 data;
	
	//_cvrt2ftaddr
	
	
	claim_needed = rtl8xxxu_sdio_claim_host_needed(func);

	if (claim_needed)
		sdio_claim_host(func);
	data = sdio_readl(func, addr, &err);
	if (claim_needed)
		sdio_release_host(func);
	if (err)
		dev_dbg(priv->dev, "%s: FAIL!(%d) addr = 0x%05x\n", __func__, err, addr);
	return data;
}

/*
static int rtl8xxxu_sdio_write8(struct rtl8xxxu_priv *priv, u16 addr, u8 val)
{
	struct rtl8xxxu_sdio_card *card = priv->card;
	struct sdio_func *func = card->func;
	int err;
	bool claim_needed;
	
	claim_needed = rtl8xxxu_sdio_claim_host_needed(func);

	if (claim_needed)
		sdio_claim_host(func);
	sdio_writeb(func, val, addr, &err);
	if (claim_needed)
		sdio_release_host(func);
	if (err)
		dev_dbg(priv->dev, "%s: FAIL!(%d) addr = 0x%05x\n", __func__, err, addr);
	return err;
}

static int rtl8xxxu_sdio_write16(struct rtl8xxxu_priv *priv, u16 addr, u16 val)
{
	struct rtl8xxxu_sdio_card *card = priv->card;
	struct sdio_func *func = card->func;
	int err;
	bool claim_needed;
	
	claim_needed = rtl8xxxu_sdio_claim_host_needed(func);

	if (claim_needed)
		sdio_claim_host(func);
	sdio_writew(func, val, addr, &err);
	if (claim_needed)
		sdio_release_host(func);
	if (err)
		dev_dbg(priv->dev, "%s: FAIL!(%d) addr = 0x%05x\n", __func__, err, addr);
	return err;
}

static int rtl8xxxu_sdio_write32(struct rtl8xxxu_priv *priv, u16 addr, u32 val)
{
	struct rtl8xxxu_sdio_card *card = priv->card;
	struct sdio_func *func = card->func;
	int err;
	bool claim_needed;
	
	claim_needed = rtl8xxxu_sdio_claim_host_needed(func);

	if (claim_needed)
		sdio_claim_host(func);
	sdio_writel(func, val, addr, &err);
	if (claim_needed)
		sdio_release_host(func);
	if (err)
		dev_dbg(priv->dev, "%s: FAIL!(%d) addr = 0x%05x\n", __func__, err, addr);
	return err;
}*/

static int rtl8xxxu_sdio_identify_chip(struct rtl8xxxu_priv *priv, u32 chip_cfg)
{
	struct rtl8xxxu_sdio_card *card = priv->card;
	
	
}

static int rtl8xxxu_sdio_probe(struct sdio_func *func,
				const struct sdio_device_id *id)
{
	struct rtl8xxxu_sdio_card *card;
	struct rtl8xxxu_priv *priv;
	struct ieee80211_hw *hw;
	int ret = 0;

	printk("Allocing hw");
	
	hw = ieee80211_alloc_hw(sizeof(struct rtl8xxxu_priv), &rtl8xxxu_ops);
	if (!hw) {
		ret = -ENOMEM;
		priv = NULL;
		goto exit;
	}

	priv = hw->priv;
	priv->hw = hw;
	priv->fops = (struct rtl8xxxu_fileops *)id->driver_data;
	priv->iops = &rtl8xxxu_sdio_intops;
	priv->dev = &func->dev;
	
	printk("Allocating CARD");
	
	card = kzalloc(sizeof(struct rtl8xxxu_sdio_card), GFP_KERNEL);
	if (!card)
		goto exit;
	
	card->priv = priv;
	card->func = func;
	priv->card = card;
	
	// TODO: Mutexes, os_intfs, devobj_init
	
	sdio_set_drvdata(func, card);
	
	printk("Claiming...");
	
	sdio_claim_host(func);
	
	printk("Enabling..");
	
	ret = sdio_enable_func(func);
	if (ret) {
		dev_dbg(priv->dev, "%s: sdio_enable_func failed (%d)\n", __func__, ret);
		goto exit;
	}
	
	card->block_transfer_length = 512;
	// maybe tx_block_mode and rx_block_mode
	
	ret = sdio_set_block_size(func, card->block_transfer_length);
	if (ret) {
		dev_dbg(priv->dev, "%s: sdio_set_block_size failed (%d)\n", __func__, ret);
		goto exit;
	}

	mutex_init(&priv->h2c_mutex);
	
	printk("HW INIT");
	
	ret = rtl8xxxu_hw_init(priv);
	if (ret)
		goto exit;
	
	return 0;

	
exit:
	sdio_release_host(func);
	sdio_disable_func(func);
	ieee80211_free_hw(hw);
	if (priv) {
		kfree(priv->fw_data);
	}
	if (card) {
		kzfree(card);
	}
	return ret;
}

static void rtl8xxxu_sdio_remove(struct sdio_func *func)
{
	struct rtl8xxxu_sdio_card *card;
	struct rtl8xxxu_priv *priv;
	struct ieee80211_hw *hw;
	
	sdio_get_drvdata(func);
	priv = card->priv;
	hw = priv->hw;
	
	// TODO: Disable all the things rtw_dev_remove
	
	sdio_release_host(func);
	kfree(priv->fw_data);
	ieee80211_unregister_hw(card->priv->hw);
	ieee80211_free_hw(card->priv->hw);
	kzfree(card);
}

static const struct sdio_device_id rtl8xxxu_sdio_id_table[] = {
	/* SDIO devices from RTL8723BS driver */
	{ SDIO_DEVICE(SDIO_VENDOR_ID_REALTEK, 0x0523), 
	.driver_data = (unsigned long)&rtl8723bu_fops },
	{ SDIO_DEVICE(SDIO_VENDOR_ID_REALTEK, 0x0623),
	.driver_data = (unsigned long)&rtl8723bu_fops },	
	{ SDIO_DEVICE(SDIO_VENDOR_ID_REALTEK, 0x0626),
	.driver_data = (unsigned long)&rtl8723bu_fops },
	/* Tested by Marek Kraus */
	{ SDIO_DEVICE(SDIO_VENDOR_ID_REALTEK, 0xb723),
	.driver_data = (unsigned long)&rtl8723bu_fops },
	{ /* end: all zeroes */                        },
};
MODULE_DEVICE_TABLE(sdio, rtl8xxxu_sdio_id_table);

static struct sdio_driver rtl8xxxu_sdio_driver = {
	.name = DRIVER_NAME,
    .probe = rtl8xxxu_sdio_probe,
	.remove = rtl8xxxu_sdio_remove,
	.id_table = rtl8xxxu_sdio_id_table,
	/*.drv = {
        .owner = THIS_MODULE,
        .pm = &brcmf_sdio_pm_ops,
        .coredump = brcmf_dev_coredump,
	},*/
};

int rtl8xxxu_sdio_register(void)
{
	return sdio_register_driver(&rtl8xxxu_sdio_driver);
}

void rtl8xxxu_sdio_deregister(void)
{
	sdio_unregister_driver(&rtl8xxxu_sdio_driver);
}

struct rtl8xxxu_intops rtl8xxxu_sdio_intops = {
	/*.read8 = rtl8xxxu_sdio_read8,
	.read16 = rtl8xxxu_sdio_read16,*/
	.read32 = rtl8xxxu_sdio_read32,
	/*.write8 = rtl8xxxu_sdio_write8,
	.write16 = rtl8xxxu_sdio_write16,
	.write32 = rtl8xxxu_sdio_write32,
	.writeN = rtl8xxxu_sdio_writeN,*/
	//.configure_beacon_queue = rtl8xxxu_usb_configure_beacon_queue,
	//.tx = rtl8xxxu_usb_tx,
	.identify_chip = rtl8xxxu_sdio_identify_chip,
	//.start = rtl8xxxu_usb_start,
	//.stop = rtl8xxxu_usb_stop
};