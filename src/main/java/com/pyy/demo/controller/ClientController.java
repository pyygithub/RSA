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
