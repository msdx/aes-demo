package com.githang;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;

public class AESCipher {
    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        final String key = "replace to your key";
        String result = encrypt(key, "AABBCC测试数据");
        System.out.println(result);
        System.out.println(decrypt(key, result));
    }

    private static String encrypt(String key, String text) {
        try {
            final byte[] keyBytes = initKey(key);
            final Key keySpec = createKey(keyBytes);
            final byte[] iv = Arrays.copyOfRange(keyBytes, 0, 16);
            final IvParameterSpec ivSpec = new IvParameterSpec(iv);
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            final byte[] raw = text.getBytes("UTF-8");
            final byte[] encoded = cipher.doFinal(raw);
            return Base64.encodeToString(encoded, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String decrypt(String key, String text) {
        try {
            final byte[] keyBytes = initKey(key);
            final Key keySpec = createKey(keyBytes);
            final byte[] iv = Arrays.copyOfRange(keyBytes, 0, 16);
            final IvParameterSpec ivSpec = new IvParameterSpec(iv);
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            final byte[] raw = Base64.decode(text.getBytes("UTF-8"), Base64.NO_WRAP);
            final byte[] encoded = cipher.doFinal(raw);
            return new String(encoded);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Key createKey(byte[] keyByte) {
        return new SecretKeySpec(keyByte, KEY_ALGORITHM);
    }

    private static byte[] initKey(String key) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final byte[] keyByte = key.getBytes("UTF-8");
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(keyByte);
    }

}