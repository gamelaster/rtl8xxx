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