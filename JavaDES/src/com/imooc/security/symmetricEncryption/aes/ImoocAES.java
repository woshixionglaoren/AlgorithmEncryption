package com.imooc.security.symmetricEncryption.aes;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.Security;

public class ImoocAES {

    private static String src = "imooc security aes";

    public static void main(String[] args) {
        jdkAES();
        bcAES();
    }

    public static void jdkAES(){
        try {
            // 生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] secretKeyEncoded = secretKey.getEncoded();

            // key转换
            Key key = new SecretKeySpec(secretKeyEncoded, "AES");

            // 加密
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5padding");
            cipher.init(Cipher.ENCRYPT_MODE,key);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk aes encrypt : " + Base64.encodeBase64String(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE,key);
            result = cipher.doFinal(result);
            System.out.println("jdk aes decrypt : " + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bcAES(){
        try {
            Security.addProvider(new BouncyCastleProvider());

            // 生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] secretKeyEncoded = secretKey.getEncoded();

            // key转换
            Key key = new SecretKeySpec(secretKeyEncoded, "AES");

            // 加密
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5padding");
            cipher.init(Cipher.ENCRYPT_MODE,key);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("bc aes encrypt : " + Base64.encodeBase64String(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE,key);
            result = cipher.doFinal(result);
            System.out.println("bc aes decrypt : " + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
