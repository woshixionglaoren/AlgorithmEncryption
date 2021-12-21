package com.imooc.security.asymmetricEncryption.rsa;

import org.apache.commons.codec.binary.Base64;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @Auther: Administrator
 * @Date: 2021/12/21 16:01
 * @Description:
 */
public class ImoocRSA {

    private static String src = "imooc security rsa";

    public static void main(String[] args) {
        jdkRSA();
    }

    public static void jdkRSA(){
        try {
            // 1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");// 获取生成密钥对实例
            keyPairGenerator.initialize(512); // 初始化大小
            KeyPair keyPair = keyPairGenerator.generateKeyPair(); // 生成密钥对
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic(); // 获取公钥
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate(); // 获取私钥
            System.out.println("rsaPublicKey = " + Base64.encodeBase64String(rsaPublicKey.getEncoded())); // 公钥较短
            System.out.println("rsaPrivateKey = " + Base64.encodeBase64String(rsaPrivateKey.getEncoded())); // 私钥较长

            // 2.私钥加密、公钥解密——加密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded()); // pkcs8:专门用来存储私钥的文件格式规范。
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // 获取KeyFactory实例
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec); // 生成私钥
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,privateKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("私钥加密、公钥解密——加密 = " + Base64.encodeBase64String(result));


            // 3.私钥加密、公钥解密——解密
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded()); // X.509:是密码学里公钥证书的格式标准。
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,publicKey);
            result = cipher.doFinal(result);
            System.out.println("私钥加密、公钥解密——解密 = " + new String(result));

            // 4.公钥加密、私钥解密——加密
            x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded()); // X.509:是密码学里公钥证书的格式标准。
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            result = cipher.doFinal(src.getBytes());
            System.out.println("公钥加密、私钥解密——加密 = " + Base64.encodeBase64String(result));

            // 5.公钥加密、私钥解密——解密
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded()); // pkcs8:专门用来存储私钥的文件格式规范。
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            result = cipher.doFinal(result);
            System.out.println("公钥加密、私钥解密——解密 = " + new String(result));

        } catch (Exception e){
            e.printStackTrace();
        }
    }
}
