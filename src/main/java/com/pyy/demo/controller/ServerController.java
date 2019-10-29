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
