package com.killua.tools.enums;

public enum Md5Enum {
	CONTENT(1), BITS(2), PNUM(3), DBIT(32);
	
	private int code;
	
	private Md5Enum(int code) {
		this.code = code;
	}
	
	public int getCode() {
		return code;
	}
}
