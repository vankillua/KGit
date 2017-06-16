package com.killua.tools.util.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;

import com.killua.tools.util.sign.SignatureUtil;

public class CertUtil {

	private static X500Name issuer;	
	private static X500Name subject;
	private static BigInteger serial;
	private static ValidityDate validity;
	private final static String DEFAULT_ISSUER = "C=CN,ST=Guangdong,L=Guangzhou,O=Guangzhou Ericsson,OU=Ericsson,CN=Killua,E=zijian.han@ericsson.com";

	public CertUtil() {
		issuer = new X500Name(DEFAULT_ISSUER);
		subject = new X500Name(DEFAULT_ISSUER);
		serial = BigInteger.probablePrime(32, new Random((long)(new Date().getTime() / 1000L)));
		validity = new ValidityDate();
	}
	
	public Certificate generateCert(PrivateKey prikey, PublicKey pubkey) throws Exception {
		Certificate cert = null;
		SubjectPublicKeyInfo spki = null;
		if (null != prikey && null != pubkey) {
			spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(PublicKeyFactory.createKey(pubkey.getEncoded()));
//			spki = SubjectPublicKeyInfo.getInstance(new ASN1InputStream(pubkey.getEncoded()).readObject());
			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, validity.getNotBefore(), validity.getNotAfter(), subject, spki);
			final AlgorithmIdentifier sig = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
			final AlgorithmIdentifier dig = new DefaultDigestAlgorithmIdentifierFinder().find(sig);
			BcECContentSignerBuilder csb = new BcECContentSignerBuilder(sig, dig);
			ContentSigner cs = csb.build(PrivateKeyFactory.createKey(prikey.getEncoded()));
			X509CertificateHolder holder = builder.build(cs);
			cert = holder.toASN1Structure();
		}
		return cert;
	}

	public X500Name getIssuer() {
		return issuer;
	}

	public X500Name getSubject() {
		return subject;
	}

	public BigInteger getSerial() {
		return serial;
	}

	public ValidityDate getValidity() {
		return validity;
	}

	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("CertUtil [issuer=");
		builder.append(issuer.toString());
		builder.append(", subject=");
		builder.append(subject.toString());
		builder.append(", serial=");
		builder.append(serial);
		builder.append(", validity=");
		builder.append(validity.toString());
		builder.append("]");
		return builder.toString();
	}
	
	public static void main(String[] args) {
		try {
			CertUtil cu = new CertUtil();
			SignatureUtil su = new SignatureUtil();
			KeyPair kp = su.generateKeyPair();
			Certificate cert = cu.generateCert(kp.getPrivate(), kp.getPublic());
			System.out.println("PriKey: " + Base64.encodeBase64String(kp.getPrivate().getEncoded()));
			System.out.println("PubKey: " + Base64.encodeBase64String(kp.getPublic().getEncoded()));
			System.out.println("Cert: " + Base64.encodeBase64String(cert.getEncoded()));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
