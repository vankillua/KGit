package com.killua.tools.util.cert;

import java.util.Date;

public class ValidityDate {
	private Date notBefore;
	private Date notAfter;
	private long oneYear = 365 * 24 * 60 * 60 * 1000L;

	public ValidityDate(int years) {
		notBefore = new Date();
		notAfter = new Date(notBefore.getTime() + oneYear * years);
	}

	public ValidityDate() {
		notBefore = new Date();
		notAfter = new Date(notBefore.getTime() + oneYear);
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public Date getNotAfter() {
		return notAfter;
	}
	
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("ValidityDate [notBefore=");
		builder.append(notBefore);
		builder.append(", notAfter=");
		builder.append(notAfter);
		builder.append("]");
		return builder.toString();
	}
}
