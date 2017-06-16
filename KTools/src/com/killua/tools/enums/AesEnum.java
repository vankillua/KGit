package com.killua.tools.enums;

public enum AesEnum {
	CONTENT(1), KEY(2), ISBASE64(3), PNUM(4);
	
	private int code;
	
	private AesEnum(int code) {
		this.code = code;
	}
	
	public int getCode() {
		return code;
	}
}
