package com.imooc.security.symmetricEncryption.des;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.Key;
import java.security.Security;

/**
 * 对称加密算法DES，加密和解密 的密钥相同
 */
public class ImoocDES {

    private static String src = "imooc security des";

    public static void main(String[] args) {
        jdkDES();
        bcDES();
    }

    public static void jdkDES(){
        try{

            // 生成KEY
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            keyGenerator.init(56);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();

            // KEY转换
            DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
            Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec); // 加密和解密 的密钥都是这一把

            // 加密
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk des encrypt = " + Hex.encodeHexString(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
            result = cipher.doFinal(result);
            System.out.println("jdk des decrypt = " + new String(result));
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void bcDES(){
        try{
            Security.addProvider(new BouncyCastleProvider());

            // 生成KEY
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES","BC");
            keyGenerator.init(56);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();

            // KEY转换
            DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
            Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

            // 加密
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // Cipher提供密码功能的类
            cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk des encrypt = " + Hex.encodeHexString(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
            result = cipher.doFinal(result);
            System.out.println("jdk des decrypt = " + new String(result));
        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
