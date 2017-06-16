package com.killua.tools.util.aes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class AESCipherUtil {
	private static SecretKeySpec secretKey;
	private static byte[] key;

	public static void setKey(String myKey) {
		MessageDigest sha = null;
		try {
			key = myKey.getBytes();
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception for setKey: " + e.toString());
		}
	}

	public static String encrypt(String strToEncrypt, String secret, boolean isBase64) {
		try {
			byte[] encryptByte;
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(1, secretKey);

			if (isBase64)
				encryptByte = cipher.doFinal(Base64.decodeBase64(strToEncrypt));
			else {
				encryptByte = cipher.doFinal(strToEncrypt.getBytes());
			}
			return Base64.encodeBase64String(encryptByte);
		} catch (Exception e) {
			System.out.println("Exception for encrypt: " + e.toString());
		}
		return null;
	}

	public static String decrypt(String strToDecrypt, String secret, boolean isBase64) {
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(2, secretKey);
			byte[] decryptByte = Base64.decodeBase64(strToDecrypt);
			byte[] decrypt = cipher.doFinal(decryptByte);
			if (isBase64) {
				return new String(Base64.encodeBase64(decrypt));
			}
			return new String(decrypt);
		} catch (Exception e) {
			System.out.println("Exception for decrypt: " + e.toString());
		}
		return null;
	}

	public static void main(String[] args) {
		String secretKey = "Ericss0n,12345";
		String originalString = "abcdefg----";
		String encryptedString = encrypt(originalString, secretKey, false);
		String decryptedString = decrypt(encryptedString, secretKey, false);

		System.out.println(originalString);
		System.out.println(encryptedString);
		System.out.println(decryptedString);
		System.out.println(decryptedString.replace("-", ""));

		String key = "8741DCFB3F1D876E8";
		String content = "VkRDUkhM/DjgWK5V1AK+4FiuVdQCvoAMeAAVQAABgBhyaGwBAwA=";
		String encrypt1 = encrypt(content, key, true);
		String decrypt1 = decrypt(encrypt1, key, true);

		System.out.println(content);
		System.out.println(encrypt1);
		System.out.println(decrypt1);
	}
}