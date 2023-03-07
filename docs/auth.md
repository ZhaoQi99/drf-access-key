# 认证方式

## Headers

* Auth-Access-Key: <Your access_key>
* Auth-Nonce: 随机字符串,每次请求都需要重新生成
* Auth-Signature: <signature>
* Auth-Timestamp: 时间戳,如:1677222787

## 签名

### 生成签名

客户端生成签名一共分三步处理：

1. 从原始请求中提取关键数据，得到一个用来签名的字符串
2. 使用加密算法和Secret Key对关键数据签名串进行加密处理,得到签名
3. 将签名所相关的所有头加入到原始HTTP请求中,得到最终HTTP请求

### 签名串🍢

```
HTTPMethod
Content-MD5
Headers
PathAndParameters
```
* HTTPMethod：HTTP的方法，全部大写，比如POST

* Content-MD5：请求中的Content-MD5头的值,可不用在Header中设置,但需参与签名串的计算。只有在请求存在Body时才计算Content-MD5头,下面是Python/Java的Content-MD5值的参考计算方式(json转字符串时要按key进行排序)：

  * Python:

    ```python
    import json,hashlib,base64
    
    body = json.dumps(body, separators=(',', ':'), sort_keys=True, ensure_ascii=False)
    md5 = base64.b64encode(hashlib.md5(body.encode()).digest()).decode()
    ```

  * Java

    ```java
    import java.security.MessageDigest;
    import org.apache.commons.codec.binary.Base64;
    // import java.math.BigInteger;
    import java.nio.charset.StandardCharsets;
    
    // fastjson
    import com.alibaba.fastjson.JSONObject;
    import com.alibaba.fastjson.serializer.SerializerFeature;
    
    String content = JSONObject.toJSONString(body, SerializerFeature.MapSortField);
    
    byte[] secretBytes;
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(content.getBytes(StandardCharsets.UTF_8));
    secretBytes = md.digest();
    
    // String md5Code = new BigInteger(1, secretBytes).toString(16);
    // for (int i = 0; i < 32 - md5Code.length(); i++) {
      // md5Code = "0" + md5Code;
    // }
    return Base64.encodeBase64String(secretBytes);
    ```

* Headers: 

  * 参与签名的Header有:

    * Auth-Access-Key

    * Auth-Nonce
  
    * Auth-Timestamp
  
  * ~~某个Header的Value为空，则使用HeaderKey+":"+"\n"参与签名,需要保留Key和英文冒号~~
  
  * 按照Header的Key排序后,按照如下格式拼接
  
    ```
    HeaderKey1 + ":" + HeaderValue1 + "\n" +
    ...
    ...
    HeaderKeyN + ":" + HeaderValueN
    ```
  


* PathAndParameters: 包含Path、Query Params,具体形式如下：

  ```python
  Path + "?" + Key1 + "=" + Value1 + "&" + Key2 + "=" + Value2 + ... "&" + KeyN + "=" + ValueN
  ```

  * Query Params需按照Key排序后按照上述方式拼接
  * 参数为空时,则直接使用Path,不需要添加?
  * Value为空时需保留等号参与签名

```http
POST
y1s21m7DKmZKNyaGDZlAyA==
Auth-Access-Key: XXXXXX
Auth-Nonce: e77a4b6f-bd5e-485e-b31c-76d8c42cfceb
Auth-Timestamp: 1677222787
/api/v1/user/?creator=xx&title=xx
```

### 签名计算

客户端从HTTP请求中提取出关键数据组装成签名串(StringToSign)后,需要对签名串使用sha256加密后,然后使用base64算法进行编码处理,形成最终的签名.

#### Python

```python
import base64,hmac,hashlib

secret_key = "<Your Secret key>"
raw_str = "<String to sign>"
x = hmac.new(secret_key.encode(), raw_str.encode(), digestmod=hashlib.sha256).digest()
signature = base64.b64encode().decode()
```

#### Java

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

String stringToSign = new String("<String to sign>");
String secretKey = new String("<Your Secret key>");

Mac hmacSha256 = Mac.getInstance("HmacSHA256");
byte[] secretKeyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
hmacSha256.init(new SecretKeySpec(secretKeyBytes, 0, secretKeyBytes.length, "HmacSHA256"));
byte[] sha256Result = hmacSha256.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));
String signature = Base64.encodeBase64String(sha256Result);
```



# 错误码表

|   HTTP 状态码    |                       Response                        |                   描述                    |
| :--------------: | :---------------------------------------------------: | :---------------------------------------: |
| 400 Bad Request  |    {"detail":"Auth-Timestamp header is required."}    |              缺少HTTP请求头               |
| 400 Bad Request  |   {"detail":"Auth-Timestamp value can't be empty."}   |              HTTP请求头为空               |
| 401 Unauthorized | {"detail":"Invalid Signature,StringToSign: POST...."} |                 签名错误                  |
|  403 Forbidden   |        {"detail":"Access key XX not exists."}         |             Access key不存在              |
|  403 Forbidden   |        {"detail":"Access key XX is disable."}         |             Access key被禁用              |
|  403 Forbidden   |    {"detail":"Access key XX has already expired."}    |             Access key已过期              |
|  403 Forbidden   |        {"detail":"Auth-Timestamp is invalid."}        |        请求头中提供的时间戳已过期         |
|  403 Forbidden   |    {"detail":"Specified nonce was used already."}     | 检测到请求重放,请求中的`Auth-Nonce`头重复 |

# 常见问题

## Invalid Signature

1. 检查json转位字符串后是否按照key进行排序
2. 使用base64对body的MD5值编码时,使用的是`bytes`,不是`hex string`



