在不同的服务器或系统之间通过API接口进行交互时，两个系统系统之间必须进行身份的验证，以满足安全上的防抵赖和防篡改。

通常情况下为了达到以上所描述的目的，我们首先向到使用**非对称加密算法**对传输的数据进行**签名**以验证发送方的身份，而`RSA`加密算法是目前比较通用的非对称加密算法，经常被用有**数字签名**及**数据加密**，且很多编程语言的标准库中都自带有`RSA`算法的库，所以实现起来也是相对简单的。

本文将使用Java标准库来实现 **RAS密钥对** 的生成及数字签名和验签，密钥对中的私钥由请求方系统妥善保管，不能泄露；而公钥则交由系统的响应方用于验证签名。

RAS使用**私钥对数据签名**，使用**公钥进行验签**，生成RSA密钥对的代码如下：
```
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
```
运行如上代码，控制台将输出一对RSA密钥对，复制该密钥对并保存，后面我们将会用到：
```
10:39:06.885 [main] INFO com.pyy.demo.util.GeneratorRSAKey - 初始化密钥，生成公钥私钥对完毕
10:39:06.887 [main] DEBUG com.pyy.demo.util.GeneratorRSAKey - ---------------------publicKey----------------------
10:39:06.887 [main] DEBUG com.pyy.demo.util.GeneratorRSAKey - MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAInOxrvSXfk8Q5v3ZCw+7gzMqab4Eh2V8GA08qyHcjU0uMgeZb+qfeipkT1XBIhku8Uzp5cHIceajpZYXsSKra8CAwEAAQ==
10:39:06.887 [main] DEBUG com.pyy.demo.util.GeneratorRSAKey - ---------------------privateKey----------------------
10:39:06.888 [main] DEBUG com.pyy.demo.util.GeneratorRSAKey - MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAic7Gu9Jd+TxDm/dkLD7uDMyppvgSHZXwYDTyrIdyNTS4yB5lv6p96KmRPVcEiGS7xTOnlwchx5qOllhexIqtrwIDAQABAkAjGeUq8CF5m20JLBF656iQ4AySd/t9R7TLfJEXewSPInUGGOCZ5anP+tzvFrfqvpRIWlbJNp8EWOda+UHqq8HpAiEA8QLkZuEEvR+Gf0PdkHM2DXSehgKUtndRYIIVOzzeASUCIQCSYMtKkg58SUmkGC6Vic2iwK1vrS1jrUh+lBeCnOONQwIgRgx5Jg2wuuc2yDaJZzqVM0P57ylA3+e+Fza3xQfj3qECIApNn+GW2EgtTG6teRHzijLrhwm2UdyTROgL+n+qFWZLAiBNRhs0yM7Lxxz36PJvnd5piheiKJ4vdNsm8GC2r6h1EA==
```

然后我们需要一个可以生成签名字符串及验证签名的工具类，这样可以方便接口的开发，代码如下：
```
package com.pyy.demo.util;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * ========================
 * RSA签名工具类
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/10/29 9:33
 * Version: v1.0
 * ========================
 */
public class JdkSignatureUtil {
    private final static String RSA = "RSA";

    private final static String MD5_WITH_RSA = "MD5withRSA";

    /**
     * 执行签名
     *
     * @param rsaPrivateKey 私钥
     * @param src           参数内容
     * @return 签名后的内容，base64后的字符串
     * @throws InvalidKeyException      InvalidKeyException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws InvalidKeySpecException  InvalidKeySpecException
     * @throws SignatureException       SignatureException
     */
    public static String executeSignature(String rsaPrivateKey, String src) throws InvalidKeyException,
            NoSuchAlgorithmException, InvalidKeySpecException, SignatureException {
        // base64解码私钥
        byte[] decodePrivateKey = Base64.getDecoder().decode(rsaPrivateKey.replace("\r\n", ""));

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decodePrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Signature signature = Signature.getInstance(MD5_WITH_RSA); //用md5生成内容摘要，再用RSA的私钥加密，进而生成数字签名
        signature.initSign(privateKey);
        signature.update(src.getBytes());
        // 生成签名
        byte[] result = signature.sign();

        // base64编码签名为字符串
        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * 验证签名
     *
     * @param rsaPublicKey 公钥
     * @param sign         签名
     * @param src          参数内容
     * @return 验证结果
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws InvalidKeySpecException  InvalidKeySpecException
     * @throws InvalidKeyException      InvalidKeyException
     * @throws SignatureException       SignatureException
     */
    public static boolean verifySignature(String rsaPublicKey, String sign, String src) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, SignatureException {
        // base64解码公钥
        byte[] decodePublicKey = Base64.getDecoder().decode(rsaPublicKey.replace("\r\n", ""));

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decodePublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Signature signature = Signature.getInstance(MD5_WITH_RSA);
        signature.initVerify(publicKey);
        signature.update(src.getBytes());
        // base64解码签名为字节数组
        byte[] decodeSign = Base64.getDecoder().decode(sign);

        // 验证签名
        return signature.verify(decodeSign);
    }
}
```
接着我们来基于SpringBoot编写一个简单的demo，看看如何实际的使用RSA算法对接口参数进行签名及验签。发送方代码如下:
```
package com.pyy.demo.controller;

import com.pyy.demo.util.JdkSignatureUtil;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/10/29 10:27
 * Version: v1.0
 * ========================
 */
public class ClientController {
    /**
     * 私钥
     */
    private final static String PRIVATE_KEY = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAic7Gu9Jd+TxDm/dkLD7uDMyppvgSHZXwYDTyrIdyNTS4yB5lv6p96KmRPVcEiGS7xTOnlwchx5qOllhexIqtrwIDAQABAkAjGeUq8CF5m20JLBF656iQ4AySd/t9R7TLfJEXewSPInUGGOCZ5anP+tzvFrfqvpRIWlbJNp8EWOda+UHqq8HpAiEA8QLkZuEEvR+Gf0PdkHM2DXSehgKUtndRYIIVOzzeASUCIQCSYMtKkg58SUmkGC6Vic2iwK1vrS1jrUh+lBeCnOONQwIgRgx5Jg2wuuc2yDaJZzqVM0P57ylA3+e+Fza3xQfj3qECIApNn+GW2EgtTG6teRHzijLrhwm2UdyTROgL+n+qFWZLAiBNRhs0yM7Lxxz36PJvnd5piheiKJ4vdNsm8GC2r6h1EA==";

    public static String sender() throws InvalidKeySpecException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, UnsupportedEncodingException {
        // 请求所需的参数
        Map<String, Object> requestParam = new HashMap<>(16);
        requestParam.put("username", "×××");
        requestParam.put("sex", "男");
        requestParam.put("city", "北京");
        requestParam.put("status", 1);

        // 将需要签名的参数内容按参数名的字典顺序进行排序，并拼接为字符串
        StringBuilder sb = new StringBuilder();
        requestParam.entrySet().stream().sorted(Comparator.comparing(Map.Entry::getKey)).forEach(entry ->
                sb.append(entry.getKey()).append("=").append(entry.getValue()).append("&")
        );
        String paramStr = sb.toString().substring(0, sb.length() - 1);

        // 使用私钥生成签名字符串
        String sign = JdkSignatureUtil.executeSignature(PRIVATE_KEY, paramStr);
        // 对签名字符串进行url编码
        String urlEncodeSign = URLEncoder.encode(sign, StandardCharsets.UTF_8.name());
        // 请求参数中需带上签名字符串
        requestParam.put("sign", urlEncodeSign);

        // 发送请求
        return postJson("http://localhost:8080/server", requestParam);
    }

    /**
     * 发送数据类型为json的post请求
     *
     * @param url
     * @param param
     * @param <T>
     * @return
     */
    public static <T> String postJson(String url, T param) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        HttpEntity<T> httpEntity = new HttpEntity<>(param, headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> responseEntity = restTemplate.postForEntity(url, httpEntity, String.class);

        return responseEntity.getBody();
    }

    public static void main(String[] args) {
        try {
            System.out.println(sender());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
接收方代码如下：
```
package com.pyy.demo.controller;

import com.pyy.demo.util.JdkSignatureUtil;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Comparator;
import java.util.Map;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/10/29 10:33
 * Version: v1.0
 * ========================
 */
@RestController
public class ServerController {
    /**
     * 公钥
     */
    private final static String PUBLIC_KEY = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAInOxrvSXfk8Q5v3ZCw+7gzMqab4Eh2V8GA08qyHcjU0uMgeZb+qfeipkT1XBIhku8Uzp5cHIceajpZYXsSKra8CAwEAAQ==";

    @PostMapping(value = "/server")
    public String server(@RequestBody Map<String, Object> param) throws InvalidKeySpecException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        // 从参数中取出签名字符串并删除，因为sign不参与字符串拼接
        String sign = (String) param.remove("sign");
        // 对签名字符串进行url解码
        String decodeSign = URLDecoder.decode(sign, StandardCharsets.UTF_8.name());

        // 将签名的参数内容按参数名的字典顺序进行排序，并拼接为字符串
        StringBuilder sb = new StringBuilder();
        param.entrySet().stream().sorted(Comparator.comparing(Map.Entry::getKey)).forEach(entry ->
                sb.append(entry.getKey()).append("=").append(entry.getValue()).append("&")
        );
        String paramStr = sb.toString().substring(0, sb.length() - 1);

        // 使用公钥进行验签
        boolean result = JdkSignatureUtil.verifySignature(PUBLIC_KEY, decodeSign, paramStr);
        if (result) {
            return "签名验证成功";
        }

        return "签名验证失败，非法请求";
    }
}
```
编写完以上代码后，启动SpringBoot项目，然后运行发送方的代码，控制台输出结果如下：
```
10:41:50.013 [main] DEBUG org.springframework.web.client.RestTemplate - HTTP POST http://localhost:8080/server
10:41:50.020 [main] DEBUG org.springframework.web.client.RestTemplate - Accept=[text/plain, application/json, application/*+json, */*]
10:41:50.033 [main] DEBUG org.springframework.web.client.RestTemplate - Writing [{city=北京, sex=男, sign=W0X%2FIsX7RzEagGUwODi3PxBnFTNNmxnjlqYX4j7liS%2BDqmcLkXXgYAQQ3bXc8D7lmvaV30Jh1J9IshAHegP3zg%3D%3D, username=×××, status=1}] as "application/json;charset=UTF-8"
10:41:50.168 [main] DEBUG org.springframework.web.client.RestTemplate - Response 200 OK
10:41:50.169 [main] DEBUG org.springframework.web.client.RestTemplate - Reading to [java.lang.String] as "text/plain;charset=UTF-8"
```

这里只是给出一个简单实例，实际项目开发中需要根据特定的业务需求，进行修改。

参考：[https://blog.51cto.com/zero01/2331063](https://blog.51cto.com/zero01/2331063)

