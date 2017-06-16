package com.killua.tools.enums;

public enum CertEnum {
	CERT(1), PNUM(2);
	
	private int code;
	
	private CertEnum(int code) {
		this.code = code;
	}
	
	public int getCode() {
		return code;
	}
}
