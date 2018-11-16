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
	/* struct dvobj_priv *dvobj = sdio_get_drvdata(func);
	PSDIO_DATA sdio_data = &dvobj->intf_data;

	if (sdio_data->sys_sdio_irq_thd && sdio_data->sys_sdio_irq_thd == current)
		return false;
	return true; */
	return true;
}

/*static u8 rtl8xxxu_sdio_read8(struct rtl8xxxu_priv *priv, u16 addr)
{
	struct sdio_func *sfunc = priv->sfunc;
	int err;
	bool claim_needed;
	u8 data;
	
	claim_needed = rtl8xxxu_sdio_claim_host_needed(sfunc);

	if (claim_needed)
		sdio_claim_host(sfunc);
	data = sdio_readb(sfunc, addr, &err);
	if (claim_needed)
		sdio_release_host(sfunc);
	if (err)
		dev_dbg(sfunc->dev, "%s: FAIL!(%d) addr = 0x%05x\n", __func__, err, addr);
	return data;
}

static u16 rtl8xxxu_sdio_read16(struct rtl8xxxu_priv *priv, u16 addr)
{
	struct sdio_func *sfunc = priv->sfunc;
	int err;
	bool claim_needed;
	u16 data;
	
	claim_needed = rtl8xxxu_sdio_claim_host_needed(sfunc);

	if (claim_needed)
		sdio_claim_host(sfunc);
	data = sdio_readw(sfunc, addr, &err);
	if (claim_needed)
		sdio_release_host(sfunc);
	if (err)
		dev_dbg(sfunc->dev, "%s: FAIL!(%d) addr = 0x%05x\n", __func__, err, addr);
	return data;
}*/

static int rtl8xxxu_sdio_probe(struct sdio_func *func,
				const struct sdio_device_id *id)
{
	struct rtl8xxxu_priv *priv;
	struct ieee80211_hw *hw;
	struct ieee80211_supported_band *sband;

	int ret;

	hw = ieee80211_alloc_hw(sizeof(struct rtl8xxxu_priv), &rtl8xxxu_ops); // TODO: This should stay in core
	if (!hw) {
		ret = -ENOMEM;
		priv = NULL;
		goto exit;
	}

	priv = hw->priv;
	priv->hw = hw;
	priv->sfunc = func;
	priv->fops = (struct rtl8xxxu_fileops *)id->driver_data;
	priv->iops = &rtl8xxxu_sdio_intops;
	
	// TODO: Mutexes, os_intfs, devobj_init
	
	sdio_claim_host(func);
	
	ret = sdio_enable_func(func);
	if (ret) {
		dev_dbg((const struct device*)func->dev, "%s: sdio_enable_func failed (%d)\n", ret);
		goto exit;
	}

	// parse???

	/*ret = rtl8xxxu_identify_chip(priv);
	if (ret) {
		dev_err(&func->dev, "Fatal - failed to identify chip\n");
		goto exit;
	}

	ret = rtl8xxxu_read_efuse(priv);
	if (ret) {
		dev_err(&func->dev, "Fatal - failed to read EFuse\n");
		goto exit;
	}

	ret = priv->fops->parse_efuse(priv);
	if (ret) {
		dev_err(&func->dev, "Fatal - failed to parse EFuse\n");
		goto exit;
	}

	rtl8xxxu_print_chipinfo(priv);*/
exit:
	ieee80211_free_hw(hw);
	return ret;
}

static void rtl8xxxu_sdio_remove(struct sdio_func *func)
{

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

void brcmf_sdio_exit(void)
{
	sdio_unregister_driver(&rtl8xxxu_sdio_driver);
}

struct rtl8xxxu_intops rtl8xxxu_sdio_intops = {
	//.read8 = rtl8xxxu_usb_read8,
	//.read16 = rtl8xxxu_usb_read16,
	//.read32 = rtl8xxxu_usb_read32,
	//.write8 = rtl8xxxu_usb_write8,
	//.write16 = rtl8xxxu_usb_write16,
	//.write32 = rtl8xxxu_usb_write32,
	//.writeN = rtl8xxxu_usb_writeN,
	//.configure_beacon_queue = rtl8xxxu_usb_configure_beacon_queue,
	//.tx = rtl8xxxu_usb_tx,
	//.start = rtl8xxxu_usb_start,
	//.stop = rtl8xxxu_usb_stop
};