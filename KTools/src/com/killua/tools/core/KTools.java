package com.killua.tools.core;

import com.killua.tools.enums.AesEnum;
import com.killua.tools.enums.CertEnum;
import com.killua.tools.enums.JksEnum;
import com.killua.tools.enums.Md5Enum;
import com.killua.tools.enums.SignEnum;
import com.killua.tools.util.aes.AESCipherUtil;
import com.killua.tools.util.cert.Cert;
import com.killua.tools.util.md5.Md5Util;
import com.killua.tools.util.sign.SignatureUtil;
import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;
import java.security.KeyPair;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringEscapeUtils;

public class KTools {

	private static void usage() {
		System.out.println(
				"KTools's Usage: \n"
				+ "\t-h: show help\n"
				+ "\t-m: md5 encryption\n"
				+ "\t-a: aes encryption\n"
				+ "\t-s: csp sms signature\n"
				+ "\t-j: get key pair from jks file\n"
				+ "\t-c: get key pair from cer file or cer string\n"
				+ "\t-k: generate key pair\n"
				+ "\t-C: generate certificate");

		System.out.println(
				"KTools's example: \n"
				+ "\tjava -jar ktools.jar -h\n"
				+ "\tjava -jar ktools.jar -m content [bits], bits defaults to 32\n"
				+ "\tjava -jar ktools.jar -a content secret_key [is_base64], is_base64 defaults to true\n"
				+ "\tjava -jar ktools.jar -s content [private_key]\n"
				+ "\tjava -jar ktools.jar -j jks_file file_pwd [private_key_pwd] [alias], private_key_pwd defaults to the same as file_pwd\n"
				+ "\tjava -jar ktools.jar -c cert_file[|cert_string]\n"
				+ "\tjava -jar ktools.jar -k\n"
				+ "\tjava -jar ktools.jar -C");
	}

	public static void main(String[] args) {
		try {
			if (args.length == 0) {
				usage();
				return;
			}
			int ch = -1;
			LongOpt[] longopts = { 
					new LongOpt("help", 0, null, 'h'), 
					new LongOpt("md5", 0, null, 'm'),
					new LongOpt("aes", 0, null, 'a'), 
					new LongOpt("sign", 0, null, 's'),
					new LongOpt("jks", 0, null, 'j'),
					new LongOpt("cer", 0, null, 'c'),
					new LongOpt("keys", 0, null, 'k'),
					new LongOpt("Cert", 0, null, 'C')
			};

			Getopt getopt = new Getopt("KTools", args, "hmasjckC", longopts);
			while (-1 != (ch = getopt.getopt())) {
				String result;
				SignatureUtil su;
				KeyPair kp;
				switch (ch) {
				case 'h':
					usage();
					break;
				case 'm':
					if (Md5Enum.BITS.getCode() > args.length) {
						usage();
					} else {
						result = Md5Util.md5(args[Md5Enum.CONTENT.getCode()], (Md5Enum.BITS.getCode() < args.length) ? Integer.valueOf(args[Md5Enum.BITS.getCode()]) : Md5Enum.DBIT.getCode());
						System.out.println("MD5:");
						System.out.println("Input: \n" + args[Md5Enum.CONTENT.getCode()] + ", " + ((Md5Enum.BITS.getCode() < args.length) ? args[Md5Enum.BITS.getCode()] : Md5Enum.DBIT.getCode()));
						System.out.println("Output: \n" + result);
					}
					break;
				case 'a':
					if (AesEnum.ISBASE64.getCode() > args.length) {
						usage();
					} else {
						result = AESCipherUtil.encrypt(args[AesEnum.CONTENT.getCode()], args[AesEnum.KEY.getCode()], (AesEnum.ISBASE64.getCode() < args.length) ? Boolean.parseBoolean(args[AesEnum.ISBASE64.getCode()]) : true);
						System.out.println("AES:");
						System.out.println("Input: \n" + args[AesEnum.CONTENT.getCode()] + ", " + args[AesEnum.KEY.getCode()] + ", " + ((AesEnum.ISBASE64.getCode() < args.length) ? Boolean.parseBoolean(args[AesEnum.ISBASE64.getCode()]) : true));
						System.out.println("Output: \n" + result);
					}
					break;
				case 's':
					if (SignEnum.PKEY.getCode() > args.length) {
						usage();
					} else {
						su = new SignatureUtil();
						if (SignEnum.PKEY.getCode() < args.length)
							su.setPrivatekey(args[SignEnum.PKEY.getCode()]);
						result = su.CspSmsSignSignature(args[SignEnum.CONTENT.getCode()]);
						System.out.println("SIGN:");
						System.out.println("Input: \n" + args[SignEnum.CONTENT.getCode()]);
						System.out.println("Private Key: \n" + ((SignEnum.PKEY.getCode() < args.length) ? args[SignEnum.PKEY.getCode()] : su.getPrivatekey()));
						if (SignEnum.PKEY.getCode() >= args.length) {
							System.out.println("Public Key: \n" + su.getPublickey());
							System.out.println("Certificate: \n" + su.getCertificate());
						}
						System.out.println("output: \n" + result);
					}
					break;
				case 'j':
					if (JksEnum.PKEY.getCode() > args.length) {
						usage();
					} else {
						su = new SignatureUtil();
						su.setJksfilename(args[JksEnum.FILE.getCode()]);
						su.setJkspassword(args[JksEnum.FPWD.getCode()]);
						if (JksEnum.PKEY.getCode() < args.length)
							su.setPrivatekeypassword(args[JksEnum.PKEY.getCode()]);
						kp = su.getKeyPairFromJks((JksEnum.ALIAS.getCode() < args.length) ? args[JksEnum.ALIAS.getCode()] : null);
						System.out.println("Get Key Pairs from JKS:");
						System.out.println("Private Key: \n" + Base64.encodeBase64String(kp.getPrivate().getEncoded()));
						System.out.println("Public Key: \n" + Base64.encodeBase64String(kp.getPublic().getEncoded()));
					}
					break;
				case 'c':
					if (CertEnum.PNUM.getCode() > args.length) {
						usage();
					} else {
						su = new SignatureUtil();
						String cert = StringEscapeUtils.unescapeJava(args[CertEnum.CERT.getCode()]);
						result = su.getPublicKeyFromCert(cert);
						System.out.println("Get Public Key from Certificate:");
						System.out.println("Certificate: \n" + args[CertEnum.CERT.getCode()]);
						System.out.println("Public Key: \n" + result);
					}
					break;
				case 'k':
					su = new SignatureUtil();
					kp = su.generateKeyPair();
					System.out.print("Generate Key Pairs:");
					System.out.println("Private Key: \n" + Base64.encodeBase64String(kp.getPrivate().getEncoded()));
					System.out.println("Public Key: \n" + Base64.encodeBase64String(kp.getPublic().getEncoded()));
					break;
				case 'C':
					su = new SignatureUtil();
					Cert cert = su.generateCertificate();
					System.out.println("Generate Certificate:");
					System.out.println("Private Key: \n" + Base64.encodeBase64String(cert.getPrivatekey().getEncoded()));
					System.out.println("Public Key: \n" + Base64.encodeBase64String(cert.getPublickey().getEncoded()));
					System.out.println("Certificate: \n" + Base64.encodeBase64String(cert.getCertificate().getEncoded()));
					break;
				default:
					usage();
					break;
				}
			}
		} catch (Exception e) {
			System.out.println("Exception for KTools: " + e);
		}
	}
}