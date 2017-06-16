package com.killua.tools.util.cert;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.Certificate;

public class Cert {
	private PrivateKey privatekey;
	private PublicKey publickey;
	private Certificate certificate;
	
	public Cert() {
	}
	
	public Cert(PrivateKey pri, PublicKey pub, Certificate cer) {
		privatekey = pri;
		publickey = pub;
		certificate = cer;
	}
	
	public PrivateKey getPrivatekey() {
		return privatekey;
	}
	
	public void setPrivatekey(PrivateKey privatekey) {
		this.privatekey = privatekey;
	}
	
	public PublicKey getPublickey() {
		return publickey;
	}
	
	public void setPublickey(PublicKey publickey) {
		this.publickey = publickey;
	}

	public Certificate getCertificate() {
		return certificate;
	}
	
	public void setCertificate(Certificate certificate) {
		this.certificate = certificate;
	}
}
