package com.killua.tools.util.sign;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.killua.tools.util.cert.Cert;
import com.killua.tools.util.cert.CertUtil;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

public class SignatureUtil {
	private static String jksfilename;
	private static String jkspassword;
	private static String privatekeypassword;
	private static PrivateKey privatekey;
	private static PublicKey publickey;
	private static Certificate certificate;
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public SignatureUtil() {
	}
/*
	private static void GenerateKeyPair() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
		kpg.initialize(256);
		KeyPair kp = kpg.generateKeyPair();
		privatekey = kp.getPrivate();
		publickey = kp.getPublic();
	}
*/	
	private static void GenerateCertificate() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
		kpg.initialize(256);
		KeyPair kp = kpg.generateKeyPair();
		privatekey = kp.getPrivate();
		publickey = kp.getPublic();
		CertUtil cu = new CertUtil();
		certificate = cu.generateCert(kp.getPrivate(), kp.getPublic());
	}
	
	private static byte[] SignSignature(String input) throws Exception {
		if (privatekey == null)
			GenerateCertificate();
		Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
		signature.initSign(privatekey);
		signature.update(Base64.decodeBase64(input));
		return decodeSign(signature.sign());
	}

	private static byte[] decodeSign(byte[] sign) throws Exception {
		DerInputStream derInputStream = new DerInputStream(sign);
		DerValue[] values = derInputStream.getSequence(2);

		byte[] random = values[0].getPositiveBigInteger().toByteArray();
		byte[] signature = values[1].getPositiveBigInteger().toByteArray();

		byte[] tokenSignature = new byte[64];
		System.arraycopy(random, (random.length > 32) ? 1 : 0, tokenSignature, (random.length < 32) ? 1 : 0, (random.length > 32) ? 32 : random.length);
		System.arraycopy(signature, (signature.length > 32) ? 1 : 0, tokenSignature, (signature.length < 32) ? 33 : 32, (signature.length > 32) ? 32 : signature.length);

		return tokenSignature;
	}

	private static boolean VerifySignature(byte[] content, byte[] sign) throws Exception {
		if (publickey == null)
			return false;
		Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
		signature.initVerify(publickey);
		signature.update(content);
		return signature.verify(encodeSign(sign));
	}

	private static byte[] encodeSign(byte[] tokenSignature) throws Exception {
		byte[] r = Arrays.copyOfRange(tokenSignature, 0, tokenSignature.length / 2);
		byte[] s = Arrays.copyOfRange(tokenSignature, tokenSignature.length / 2, tokenSignature.length);

		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DEROutputStream derOutputStream = new DEROutputStream(byteArrayOutputStream);
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new ASN1Integer(new BigInteger(1, r)));
		v.add(new ASN1Integer(new BigInteger(1, s)));
		derOutputStream.writeObject(new DERSequence(v));
		return byteArrayOutputStream.toByteArray();
	}

	public String CspSmsSignSignature(String sms) throws Exception {
		if ((sms == null) || (sms.isEmpty())) {
			System.out.println("CspSmsSignSignature: The input parameter is null!");
			return "";
		}
		byte[] content = Base64.decodeBase64(sms);
		byte fixedTag = (byte) 0x81;
		byte fixedLength = (byte) 0x40;
		byte[] sign = SignSignature(sms);
		content = ArrayUtils.add(content, fixedTag);
		content = ArrayUtils.add(content, fixedLength);
		byte[] contentSign = ArrayUtils.addAll(content, sign);
		return Base64.encodeBase64String(contentSign);
	}

	public boolean CspSmsVerifySignature(String sms) throws Exception {
		if ((sms == null) || (sms.isEmpty())) {
			System.out.println("CspSmsVerifySignature: The input parameter is null!");
			return false;
		}
		byte[] contentSignByte = Base64.decodeBase64(sms);
		byte[] contentByte = Arrays.copyOfRange(contentSignByte, 0, contentSignByte.length - 64 - 2);
		byte[] signByte = Arrays.copyOfRange(contentSignByte, contentSignByte.length - 64, contentSignByte.length);
		return VerifySignature(contentByte, signByte);
	}

	public String getPubKeyStrFromJks(String alias) throws Exception {
		PublicKey pk;
		if ((jksfilename == null) || (jksfilename.isEmpty()) || (jkspassword == null))
			return "";
		KeyStore ks = KeyStore.getInstance("jks");
		ks.load(new FileInputStream(jksfilename), jkspassword.toCharArray());

		if ((alias == null) || (alias.isEmpty()))
			pk = ks.getCertificate((String) ks.aliases().nextElement()).getPublicKey();
		else {
			pk = ks.getCertificate(alias).getPublicKey();
		}
		return Base64.encodeBase64String(pk.getEncoded());
	}

	public PublicKey getPublicKeyFromJks(String alias) throws Exception {
		PublicKey pk;
		if ((jksfilename == null) || (jksfilename.isEmpty()) || (jkspassword == null))
			return null;
		KeyStore ks = KeyStore.getInstance("jks");
		ks.load(new FileInputStream(jksfilename), jkspassword.toCharArray());

		if ((alias == null) || (alias.isEmpty()))
			pk = ks.getCertificate((String) ks.aliases().nextElement()).getPublicKey();
		else {
			pk = ks.getCertificate(alias).getPublicKey();
		}
		return pk;
	}

	public String getPriKeyStrFromJks(String alias) throws Exception {
		PrivateKey pk;
		if ((jksfilename == null) || (jksfilename.isEmpty()) || (jkspassword == null))
			return "";
		KeyStore ks = KeyStore.getInstance("jks");
		ks.load(new FileInputStream(jksfilename), jkspassword.toCharArray());

		if ((alias == null) || (alias.isEmpty()))
			pk = (PrivateKey) ks.getKey((String) ks.aliases().nextElement(), (privatekeypassword == null) ? jkspassword.toCharArray() : privatekeypassword.toCharArray());
		else {
			pk = (PrivateKey) ks.getKey(alias, (privatekeypassword == null) ? jkspassword.toCharArray() : privatekeypassword.toCharArray());
		}
		return Base64.encodeBase64String(pk.getEncoded());
	}

	public PrivateKey getPriateKeyFromJks(String alias) throws Exception {
		PrivateKey pk;
		if ((jksfilename == null) || (jksfilename.isEmpty()) || (jkspassword == null))
			return null;
		KeyStore ks = KeyStore.getInstance("jks");
		ks.load(new FileInputStream(jksfilename), jkspassword.toCharArray());

		if ((alias == null) || (alias.isEmpty()))
			pk = (PrivateKey) ks.getKey((String) ks.aliases().nextElement(), (privatekeypassword == null) ? jkspassword.toCharArray() : privatekeypassword.toCharArray());
		else {
			pk = (PrivateKey) ks.getKey(alias, (privatekeypassword == null) ? jkspassword.toCharArray() : privatekeypassword.toCharArray());
		}
		return pk;
	}

	public KeyPair getKeyPairFromJks(String alias) throws Exception {
		PublicKey pub;
		PrivateKey pri;
		if ((jksfilename == null) || (jksfilename.isEmpty()) || (jkspassword == null))
			return null;
		KeyStore ks = KeyStore.getInstance("jks");
		ks.load(new FileInputStream(jksfilename), jkspassword.toCharArray());

		if ((alias == null) || (alias.isEmpty())) {
			pub = ks.getCertificate((String) ks.aliases().nextElement()).getPublicKey();
			pri = (PrivateKey) ks.getKey((String) ks.aliases().nextElement(), (privatekeypassword == null) ? jkspassword.toCharArray() : privatekeypassword.toCharArray());
		} else {
			pub = ks.getCertificate(alias).getPublicKey();
			pri = (PrivateKey) ks.getKey(alias, (privatekeypassword == null) ? jkspassword.toCharArray() : privatekeypassword.toCharArray());
		}
		return new KeyPair(pub, pri);
	}

	public KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
		kpg.initialize(256);
		return kpg.generateKeyPair();
	}

	public String getPublicKeyFromCert(String cert) throws Exception {
		if(cert == null || cert.isEmpty())
			return "";
		File file = new File(cert);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate xcert;
		if(file.exists() && file.isFile()) {
			FileInputStream fis = new FileInputStream(cert);
			xcert = (X509Certificate) cf.generateCertificate(fis);
		} else {
			byte[] bcert = Base64.decodeBase64(cert.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "").replaceAll(" ", "").trim());
			ByteArrayInputStream bais = new ByteArrayInputStream(bcert);
			xcert = (X509Certificate) cf.generateCertificate(bais);
		}
		return Base64.encodeBase64String(xcert.getPublicKey().getEncoded());
	}
	
	public Cert generateCertificate() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
		kpg.initialize(256);
		KeyPair kp = kpg.generateKeyPair();
		CertUtil cu = new CertUtil();
		return new Cert(kp.getPrivate(), kp.getPublic(), cu.generateCert(kp.getPrivate(), kp.getPublic())); 
	}
	
	public String getJksfilename() {
		return jksfilename;
	}

	public void setJksfilename(String filename) {
		jksfilename = filename;
	}

	public String getJkspassword() {
		return jkspassword;
	}

	public void setJkspassword(String password) {
		jkspassword = password;
	}

	public String getPrivatekeypassword() {
		return privatekeypassword;
	}

	public void setPrivatekeypassword(String privatekeypwd) {
		privatekeypassword = privatekeypwd;
	}

	public String getPrivatekey() {
		return Base64.encodeBase64String(privatekey.getEncoded());
	}

	public PrivateKey getPrivateKey() {
		return privatekey;
	}
	
	public void setPrivatekey(String prikey) throws Exception {
		privatekey = KeyFactory.getInstance("ECDSA", "BC").generatePrivate(new PKCS8EncodedKeySpec(Base64.decodeBase64(prikey)));
	}

	public String getPublickey() {
		return Base64.encodeBase64String(publickey.getEncoded());
	}

	public PublicKey getPublicKey() {
		return publickey;
	}
	
	public void setPublickey(String pubkey) throws Exception {
		publickey = KeyFactory.getInstance("ECDSA", "BC").generatePublic(new X509EncodedKeySpec(Base64.decodeBase64(pubkey)));
	}

	public String getCertificate() throws Exception {
		return Base64.encodeBase64String(certificate.getEncoded());
	}
	
	public Certificate getBCCertificate() {
		return certificate;
	}
	
	public static void main(String[] args) {
		try {
			SignatureUtil su = new SignatureUtil();
/*			String jksfile = "D:\\用户目录\\桌面\\Geely-CSP.jks";
			String jkspwd = "abcdefg";
			String sms = "VkRDTVRQ/A/gWRPEwABH4FkTxMAAR6AC0GgAAQA=\r\n";
			su.setJksfilename(jksfile);
			su.setJkspassword(jkspwd);
//			su.setPrivatekeypassword("");
			privatekey = su.getPriateKeyFromJks("1");
			String smsContentSign = su.CspSmsSignSignature(sms);
			System.out.println("content: " + sms + "\ncontent-sign: " + smsContentSign);

			publickey = su.getPublicKeyFromJks("1");
			boolean flag = su.CspSmsVerifySignature(smsContentSign);
			System.out.println("\nverify signature: " + flag);
			System.out.println("Private Key: " + Base64.encodeBase64String(privatekey.getEncoded()));
			System.out.println("Public Key: " + Base64.encodeBase64String(publickey.getEncoded()));
*/			
//			String fcer = "D:\\用户目录\\桌面\\1.cer";
			String fcer = "MIICMDCCAdWgAwIBAgIFAMXi8u8wCgYIKoZIzj0EAwIwgZ4xCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEbMBkGA1UECgwSR3Vhbmd6aG91IEVyaWNzc29uMREwDwYDVQQLDAhFcmljc3NvbjEPMA0GA1UEAwwGS2lsbHVhMSYwJAYJKoZIhvcNAQkBFhd6aWppYW4uaGFuQGVyaWNzc29uLmNvbTAeFw0xNzA2MTQwODEzNThaFw0xODA2MTQwODEzNThaMIGeMQswCQYDVQQGEwJDTjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3pob3UxGzAZBgNVBAoMEkd1YW5nemhvdSBFcmljc3NvbjERMA8GA1UECwwIRXJpY3Nzb24xDzANBgNVBAMMBktpbGx1YTEmMCQGCSqGSIb3DQEJARYXemlqaWFuLmhhbkBlcmljc3Nvbi5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQYnxfUwL6Tnhlsx03CSQTmXSdNFawxhrchJXkcdCTLi06MUwQ3A7aqs07d7YGG4JuIyLI1B2HeiaUf3yGWNEahMAoGCCqGSM49BAMCA0kAMEYCIQCPRSIxZkAy8CTxSsws3mSpGHPXfGSssMgzMl86UFrLygIhAJWJLhf6y5cdZrVCWd4XAHrvhLm9WGQtBHVuJibMZREB";
			String pub = su.getPublicKeyFromCert(fcer);
			System.out.println("\nFile: " + fcer + "\nPublic Key: " + pub);
			String fcer1 = "-----BEGIN CERTIFICATE-----MIIDQTCCAuegAwIBAgIUJ8KhyafUIE5/WC6+fvzisWSXO7swCgYIKoZIzj0EAwIwgeoxJzAlBgNVBAMMHkdsb2JhbCBWZWhpY2xlIElzc3VpbmcgVGVzdCBDQTEmMCQGA1UECwwdR2VlbHkgQXV0b21vYmlsZSBIb2xkaW5ncyBMdGQxLjAsBgNVBAoMJVpoZWppYW5nIEdlZWx5IEhvbGRpbmcgR3JvdXAgQ28uLCBMdGQxETAPBgNVBAcMCEhhbmd6aG91MREwDwYDVQQIDAhaaGVqaWFuZzELMAkGA1UEBhMCQ04xFTATBgoJkiaJk/IsZAEZFgVHZWVseTEdMBsGCgmSJomT8ixkARkWDUNvbm5lY3RlZCBDYXIwIBcNMTcwNjE5MDI0NDMzWhgPMjA2NzA2MTkwMjQ0MzNaMIG1MRowGAYDVQQDDBE4NzQxRENGQjNGMUQ4NzZFODEPMA0GA1UECwwGMjAxNjMzMQ0wCwYDVQQKDAQyMDE2MQswCQYDVQQHDAJDTjERMA8GA1UECAwIWmhlamlhbmcxCzAJBgNVBAYTAkNOMRQwEgYKCZImiZPyLGQBAQwEVEVNMjEZMBcGCgmSJomT8ixkARkWCW1vZGVsQ29kZTEZMBcGCgmSJomT8ixkARkWCUdlZWx5IENTUDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNNE+DoaSJhKT0BGqvKSn9nfKRjF5elhgYPYNCJt0vbMhh1rrPgYxY+R5Dox4tdQNNlp2nKZUrAkvvQ1dzFKTkajgZswgZgwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFMqimubgj6LneDVc2s57YMIAzJFuMDEGCCsGAQUFBwEBBCUwIzAhBggrBgEFBQcwAYYVaHR0cDovL29jc3AuZ2VlbHkuY29tMB0GA1UdDgQWBBT3wyDgqJLrH06e4PU7iuIkVLW2WDAKBggqhkjOPQQDAgNIADBFAiEAm2hsxTyyxS6iIVO+7DEeoWWv43bw0C284a6DAZt/B4YCIH7K3Z63O1LMXGHp83QHBgI2FAtPPW438wqZ6ivHkW2j-----END CERTIFICATE-----";
			String pub1 = su.getPublicKeyFromCert(fcer1);
			System.out.println("\nFile: " + fcer1 + "\nPublic Key: " + pub1);
			String fcer2 = "-----BEGIN CERTIFICATE-----\nMIIDQTCCAuegAwIBAgIUJ8KhyafUIE5/WC6+fvzisWSXO7swCgYIKoZIzj0EAwIw\ngeoxJzAlBgNVBAMMHkdsb2JhbCBWZWhpY2xlIElzc3VpbmcgVGVzdCBDQTEmMCQG\nA1UECwwdR2VlbHkgQXV0b21vYmlsZSBIb2xkaW5ncyBMdGQxLjAsBgNVBAoMJVpo\nZWppYW5nIEdlZWx5IEhvbGRpbmcgR3JvdXAgQ28uLCBMdGQxETAPBgNVBAcMCEhh\nbmd6aG91MREwDwYDVQQIDAhaaGVqaWFuZzELMAkGA1UEBhMCQ04xFTATBgoJkiaJ\nk/IsZAEZFgVHZWVseTEdMBsGCgmSJomT8ixkARkWDUNvbm5lY3RlZCBDYXIwIBcN\nMTcwNjE5MDI0NDMzWhgPMjA2NzA2MTkwMjQ0MzNaMIG1MRowGAYDVQQDDBE4NzQx\nRENGQjNGMUQ4NzZFODEPMA0GA1UECwwGMjAxNjMzMQ0wCwYDVQQKDAQyMDE2MQsw\nCQYDVQQHDAJDTjERMA8GA1UECAwIWmhlamlhbmcxCzAJBgNVBAYTAkNOMRQwEgYK\nCZImiZPyLGQBAQwEVEVNMjEZMBcGCgmSJomT8ixkARkWCW1vZGVsQ29kZTEZMBcG\nCgmSJomT8ixkARkWCUdlZWx5IENTUDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\nBNNE+DoaSJhKT0BGqvKSn9nfKRjF5elhgYPYNCJt0vbMhh1rrPgYxY+R5Dox4tdQ\nNNlp2nKZUrAkvvQ1dzFKTkajgZswgZgwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQM\nMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFMqimubgj6LneDVc2s57YMIAzJFuMDEG\nCCsGAQUFBwEBBCUwIzAhBggrBgEFBQcwAYYVaHR0cDovL29jc3AuZ2VlbHkuY29t\nMB0GA1UdDgQWBBT3wyDgqJLrH06e4PU7iuIkVLW2WDAKBggqhkjOPQQDAgNIADBF\nAiEAm2hsxTyyxS6iIVO+7DEeoWWv43bw0C284a6DAZt/B4YCIH7K3Z63O1LMXGHp\n83QHBgI2FAtPPW438wqZ6ivHkW2j\n-----END CERTIFICATE-----\n";
			String pub2 = su.getPublicKeyFromCert(fcer2);
			System.out.println("\nFile: " + fcer2 + "\nPublic Key: " + pub2);
/*
			KeyPair kp = su.generateKeyPair();
			String pri1 = Base64.encodeBase64String(kp.getPrivate().getEncoded());
			String pub1 = Base64.encodeBase64String(kp.getPublic().getEncoded());
			su.setPrivatekey(pri1);
			su.setPublickey(pub1);
			System.out.println("\nPrivateKey:\nin: " + pri1 + "\nout: " + su.getPrivatekey());
			System.out.println("PublicKey:\nin: " + pub1 + "\nout: " + su.getPublickey());
			*/
		} catch (Exception e) {
			System.out.println("Exception for SignatureUtil: " + e);
		}
	}
}