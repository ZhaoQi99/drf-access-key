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

* Content-MD5：请求中的Content-MD5头的值,可不用在Header中设置,但需参与签名串的计算。只有在请求存在Body时才计算Content-MD5头,否则使用空字符串代替.下面是Python/Java的Content-MD5值的参考计算方式(json转字符串时要按key进行排序)：

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

# SDK

* Python
  <details>
    <summary>client.py</summary>

  ```python
  import base64
  import hashlib
  import hmac
  import json
  import time
  import uuid
  from urllib.parse import urljoin

  import requests

  AUTH_HEADER = "Auth-Access-Key"
  NONCE_HEADER = "Auth-Nonce"
  TIMESTAMP_HEADER = "Auth-Timestamp"
  SIGNATURE_HEADER = "Auth-Signature"
  SIGNED_HEADERS = (AUTH_HEADER, NONCE_HEADER, TIMESTAMP_HEADER)


  class Client:
      def __init__(self, endpoint, access_key, secret_key) -> None:
          self._client = requests.Session()
          self.access_key = access_key
          self.secret_key = secret_key
          self.endpoint = endpoint

      def get_signed_headers(self, headers):
          return "\n".join(
              [f"{header}:{headers.get(header, '')}" for header in sorted(SIGNED_HEADERS)]
          )

      def tuple2str(self, t):
          return "&".join(["=".join(item) for item in t])

      def get_path_and_params(self, path, params=None):
          if params:
              return "%s?%s" % (path, self.tuple2str(sorted(params.items())))
          return path

      def get_headers(self) -> dict:
          return {
              AUTH_HEADER: self.access_key,
              NONCE_HEADER: "83a1ca5507564efd891ad8d6e04529ee",
              TIMESTAMP_HEADER: 1677636324,
          }
          headers = {
              AUTH_HEADER: self.access_key,
              NONCE_HEADER: str(uuid.uuid4()),
              TIMESTAMP_HEADER: str(int(time.time())),
          }
          return headers

      def get_content_md5(self, body):
          if not body:
              return ""

          body_str = json.dumps(
              body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
          ).encode()
          return base64.b64encode(hashlib.md5(body_str).digest()).decode()

      def _sign(self, raw_str: str, secret_key: str):
          return base64.b64encode(
              hmac.new(
                  secret_key.encode(), raw_str.encode(), digestmod=hashlib.sha256
              ).digest()
          ).decode()

      def get_signature(self, string_to_sign):
          return self._sign(string_to_sign, self.secret_key)

      def request(self, method, path, params=None, json=None, **kwargs):
          url = urljoin(self.endpoint, path)
          headers = self.get_headers()
          signed_tuple = (
              method.upper(),
              self.get_content_md5(json),
              self.get_signed_headers(headers),
              self.get_path_and_params(path, params),
          )
          string_to_sign = "\n".join(signed_tuple)
          headers[SIGNATURE_HEADER] = self.get_signature(string_to_sign)

					return self._client.request(
							method, url, headers=headers, params=params, json=json, **kwargs
					)

      def get(self, path, params=None, **kwargs):
          return self.request("GET", path, params=params, **kwargs)

      def post(self, path, json=None, **kwargs):
          return self.request("POST", path, json=json, **kwargs)

  if __name__ == "__main__":
      access_key = "Mt42zgcrjnQiZK6ETahxSa1TCzXrpNdSxxGfYmWxvuk"
      secret_key = "_E0AOqZ-R490wn2idowfxRvQej3tBWp6zUoLE2eKrpM"
      client = Client("http://localhost:8000", access_key, secret_key)
      body = {
          "identifier": "drillchange",
          "start_time": "2023-02-28 20:00:00",
          "operate": "DELPOY",
          "obtype": "CHANGE",
          "end_time": "2023-02-28 21:00:00",
          "description": "因世纪互联jdfcloud.com备案恢复，技术保障部-网络运维组将于2023-2-28（周二）20:00:00-21:00:00进行jrss-hb.jdfcloud.com域名切换操作，理论无影响，极端情况影响csia_store业务，各相关方请知悉，感谢！",
          "source": "online",
          "scopes": ["金科"],
          "department": "京东集团-京东科技-京东云事业部-技术保障部-平台运维组",
          "title": "jrss-hb.jdfcloud.com切回世纪互联VIP",
          "operator": "jiazhijiang",
          "source_url": "http://magicflow.cbpmgt.com/online/process/pjDataViewFromFiNo/drillChange202302284LX31",
      }
			rep = client.post("/api/v1/change_board/changes", json=body)
			print(rep.json())

  ```
  </details>

* Java
  <details>
    <summary>client.java</summary>

    ```java
    package openapi;

    import com.alibaba.fastjson.JSONObject;
    import com.alibaba.fastjson.serializer.SerializerFeature;
    import org.apache.commons.codec.binary.Base64;
    import org.apache.commons.io.FileUtils;

    import javax.crypto.Mac;
    import javax.crypto.spec.SecretKeySpec;
    import java.io.File;
    import java.net.URI;
    import java.net.http.HttpClient;
    import java.net.http.HttpRequest;
    import java.net.http.HttpResponse;
    import java.nio.charset.StandardCharsets;
    import java.security.InvalidKeyException;
    import java.security.MessageDigest;
    import java.security.NoSuchAlgorithmException;
    import java.util.*;
    import java.util.stream.Collectors;

    public class Client {
        private static final String AUTH_HEADER = "Auth-Access-Key";
        private static final String NONCE_HEADER = "Auth-Nonce";
        private static final String TIMESTAMP_HEADER = "Auth-Timestamp";
        private static final String SIGNATURE_HEADER = "Auth-Signature";
        private static final List<String> SIGNED_HEADERS = Arrays.asList(AUTH_HEADER, NONCE_HEADER, TIMESTAMP_HEADER);

        private final String endpoint;
        private final String accessKey;
        private final String secretKey;
        private final HttpClient _client;

        public Client(String endpoint, String accessKey, String secretKey) {
            this.endpoint = endpoint;
            this.accessKey = accessKey;
            this.secretKey = secretKey;
            this._client = HttpClient.newHttpClient();
        }

        public static void main(String[] args) {
            String accessKey = "Mt42zgcrjnQiZK6ETahxSa1TCzXrpNdSxxGfYmWxvuk";
            String secretKey = "_E0AOqZ-R490wn2idowfxRvQej3tBWp6zUoLE2eKrpM";
            String endpoint = "http://localhost:8000";
            Client client = new Client(endpoint, accessKey, secretKey);

            File file = new File("data/a.json");
            try {
                String bodyStr = FileUtils.readFileToString(file);
                JSONObject body = JSONObject.parseObject(bodyStr);
    //            client.post("/api/v1/change_board/changes",body);

                Map<String, String> params = new HashMap<>();
                params.put("a", "1");
                params.put("b", "22");
                client.get("/api/v1/change_board/changes", params);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private String getSignedHeaders(Map<String, String> headers) {
            return this.SIGNED_HEADERS.stream()
                    .sorted()
                    .map(header -> header + ":" + headers.getOrDefault(header, ""))
                    .collect(Collectors.joining("\n"));
        }

        private String tuple2str(List<Map.Entry<String, String>> t) {
            return t.stream()
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(Collectors.joining("&"));
        }

        private String getPathAndParams(String path, Map<String, String> params) {
            if (params != null && !params.isEmpty()) {
                List<Map.Entry<String, String>> sortedParams = new ArrayList<>(params.entrySet());
                Collections.sort(sortedParams, Comparator.comparing(Map.Entry::getKey));
                return path + "?" + this.tuple2str(sortedParams);
            }
            return path;
        }

        private Map<String, String> getHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put(this.AUTH_HEADER, accessKey);
            headers.put(this.NONCE_HEADER, UUID.randomUUID().toString());
            headers.put(this.TIMESTAMP_HEADER, String.valueOf(System.currentTimeMillis() / 1000));
            return headers;
        }

        private String getContentMD5(Object body) throws NoSuchAlgorithmException {
            if (body == null) {
                return "";
            }
            String bodyStr = JSONObject.toJSONString(body, SerializerFeature.MapSortField);
            byte[] bodyBytes = bodyStr.getBytes(StandardCharsets.UTF_8);
            byte[] md5Bytes = MessageDigest.getInstance("MD5").digest(bodyBytes);
            return Base64.encodeBase64String(md5Bytes);
        }

        private String sign(String rawStr, String secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            sha256Hmac.init(new SecretKeySpec(secretKey.getBytes(), "HmacSHA256"));
            byte[] signatureBytes = sha256Hmac.doFinal(rawStr.getBytes());
            return Base64.encodeBase64String(signatureBytes);
        }

        private String getSignature(String stringToSign) throws NoSuchAlgorithmException, InvalidKeyException {
            return this.sign(stringToSign, this.secretKey);
        }

        private HttpResponse request(String method, String path, Map<String, String> params, JSONObject body) throws Exception {
            URI uri = new URI(endpoint).resolve(path);

            if (params != null) {
                uri = uri.resolve("?" + params.entrySet()
                        .stream()
                        .map(entry -> entry.getKey() + "=" + entry.getValue())
                        .collect(Collectors.joining("&")));
            }

            Map<String, String> headers = getHeaders();

            List<String> signedStringList = new ArrayList<>(Arrays.asList(method.toUpperCase(),
                    this.getContentMD5(body),
                    this.getSignedHeaders(headers),
                    this.getPathAndParams(path, params)));
            String stringToSign = String.join("\n", signedStringList);
            headers.put(this.SIGNATURE_HEADER, this.getSignature(stringToSign));

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(uri)
                    .method(method.toUpperCase(),
                            body != null ? HttpRequest.BodyPublishers.ofString(body.toString()) : HttpRequest.BodyPublishers.noBody());

            for (Map.Entry<String, String> entry : headers.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
            HttpResponse response = this._client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());

            return response;

        }

        public HttpResponse get(String path, Map<String, String> params) throws Exception {
            return this.request("GET", path, params, null);
        }

        public HttpResponse post(String path, JSONObject body) throws Exception {
            return this.request("POST", path, null, body);
        }
    }
    ```
</details>


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



