package com.killua.tools.enums;

public enum JksEnum {
	FILE(1), FPWD(2), PKEY(3), ALIAS(4), PNUM(5);
	
	private int code;
	
	private JksEnum(int code) {
		this.code = code;
	}
	
	public int getCode() {
		return code;
	}
}
