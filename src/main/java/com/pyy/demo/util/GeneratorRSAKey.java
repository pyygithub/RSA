package com.pyy.demo.util;

import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * ========================
 * 生成RSA公/私钥对
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/10/29 9:19
 * Version: v1.0
 * ========================
 */
@Slf4j
public class GeneratorRSAKey {
    /**
     * 初始化密钥，生成公钥私钥对
     *
     * @return Object[]
     * @throws NoSuchAlgorithmException
     */
    private Object[] initSecretkey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);// 可以理解为：加密后的密文长度，实际原文要小些 越大 加密解密越慢
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        log.info("初始化密钥，生成公钥私钥对完毕");

        String publicKey = Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());
        log.debug("---------------------publicKey----------------------");
        log.debug(publicKey);
        log.debug("---------------------privateKey----------------------");
        log.debug(privateKey);


        Object[] keyPairArr = new Object[2];
        keyPairArr[0] = publicKey;
        keyPairArr[1] = privateKey;

        return keyPairArr;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        GeneratorRSAKey generatorRSAKey = new GeneratorRSAKey();
        generatorRSAKey.initSecretkey();
    }
}
