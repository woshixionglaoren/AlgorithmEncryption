package com.imooc.security.asymmetricEncryption.dh;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * @Auther: Administrator
 * @Date: 2021/12/8 14:55
 * @Description: 非对称加密，DH算法
 */
public class ImoocDH {

    private static String src = "imooc security dh";

    public static void main(String[] args) {
        jdkDH();
    }

    public static void jdkDH(){
        try{
            /**
             * Java在使用加密算法编程中的非对称密码时，用到的DH密钥交换算法出现以下错误信息：
             * 密钥所用的算法不被支持，这个是由于JDK8 update 161之后，DH的密钥长度至少为512位，但AES算法密钥不能达到这样的长度，长度不一致所以导致报错。
             * 解决的方法：
             * 将 -Djdk.crypto.KeyAgreement.legacyKDF=true 写入JVM系统变量中，可以在eclipse的run configurations里配置系统变量：
             */
            System.getProperties().setProperty("jdk.crypto.KeyAgreement.legacyKDF", "true");
            // 1.初始化发送方密钥
            KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
            senderKeyPairGenerator.initialize(512);
            KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();
            byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded(); // 发送方公钥，发送给接收方（网络，文件）

            // 2.初始化接收方密钥
            KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc); // 使用发送方的公钥
            PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);
            DHParameterSpec dhParameterSpec = ((DHPublicKey) receiverPublicKey).getParams();
            KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
            receiverKeyPairGenerator.initialize(dhParameterSpec);
            KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair(); // 生成接收方的密钥对
            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
            byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();

            // 3.密钥构建
            KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
            receiverKeyAgreement.init(receiverPrivateKey);
            receiverKeyAgreement.doPhase(receiverPublicKey,true);
            SecretKey receiverDESKey = receiverKeyAgreement.generateSecret("DES");

            KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
            x509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);
            PublicKey senderPublicKey = senderKeyFactory.generatePublic(x509EncodedKeySpec);
            KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
            senderKeyAgreement.init(senderKeyPair.getPrivate());
            senderKeyAgreement.doPhase(senderPublicKey,true);
            SecretKey senderDESKey = senderKeyAgreement.generateSecret("DES");
            if (Objects.equals(receiverDESKey,senderDESKey)){
                System.out.println("双方密钥相同。");
            }

            // 4.加密
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE,senderDESKey);
            byte[] encryptResult = cipher.doFinal(src.getBytes());
            System.out.println("jdk dh encryt ： " + Base64.encodeBase64String(encryptResult));

            // 5.解密
            cipher.init(Cipher.DECRYPT_MODE,receiverDESKey);
            encryptResult = cipher.doFinal(encryptResult);
            System.out.println("jdk dh decryt ： " + new String(encryptResult));

        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
