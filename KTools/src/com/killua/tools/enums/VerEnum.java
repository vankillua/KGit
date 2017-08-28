package com.killua.tools.enums;

public enum VerEnum {
	SIGN(1), PUBK(2), PNUM(3);
	
	private int code;
	
	private VerEnum(int code) {
		this.code = code;
	}
	
	public int getCode() {
		return code;
	}
}
