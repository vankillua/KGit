package com.killua.tools.enums;

public enum SignEnum {
	CONTENT(1), PKEY(2), PNUM(3);
	
	private int code;
	
	private SignEnum(int code) {
		this.code = code;
	}
	
	public int getCode() {
		return code;
	}
}
