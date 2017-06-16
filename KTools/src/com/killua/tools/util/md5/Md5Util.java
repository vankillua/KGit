package com.killua.tools.util.md5;

import java.security.MessageDigest;

public class Md5Util {
	public static String md5(String in, int bits) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(in.getBytes("UTF-8"));
			byte[] bytes = md.digest();
			StringBuilder sb = new StringBuilder(32);
			for (int offset = 0; offset < bytes.length; ++offset) {
				int i = bytes[offset];
				if (i < 0)
					i += 256;
				if (i < 16)
					sb.append("0");
				sb.append(Integer.toHexString(i));
			}
			if (bits == 16) {
				return sb.toString().substring(8, 24);
			}
			return sb.toString();
		} catch (Exception e) {
			System.out.println("Exception for md5: " + e.toString());
		}
		return "";
	}

	public static void main(String[] args) {
		try {
			String in = "{\"MSISDN\":\"8613800138020\",\"requestId\":\"0120190920\",\"contentType\":\"2\",\"smsContent\":\"VkRDU1RO+HvgWRF+BwIO4FkRfgcCDgABYAAsAIELl5iAAAAAwIAAAAAAZAABAAEBAAABAQFz4FkRfgcAAAEB\",\"token\":\"62jrr6PTnRJ33lQyc6v2sjeI6eBF7tcSe0CPJAuKbnspflAanTe1tqy4NcKRbagO\"}Ubn3aDACYgA8fCC39xVkbElX9P8ai27M5kcqtCtfhpJplgAY94B3SKt9eQzEgMK9";
			String out = md5(in, 32);
			System.out.println("in: " + in + "\nout1: " + out + "\nout2: " + out.toUpperCase());
		} catch (Exception e) {
			System.out.println("Exception for md5: " + e);
		}
	}
}