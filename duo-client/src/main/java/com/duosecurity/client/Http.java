package com.duosecurity.client;

import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import okhttp3.CertificatePinner;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONObject;

public class Http {
  public static final int BACKOFF_FACTOR = 2;
  public static final int INITIAL_BACKOFF_MS = 1000;
  public static final int MAX_BACKOFF_MS = 32000;
  public static final int DEFAULT_TIMEOUT_SECS = 60;
  private static final int RATE_LIMIT_ERROR_CODE = 429;

  public static final String UserAgentString = "Duo API Java/0.7.1-SNAPSHOT";

  private final String method;
  private final String host;
  private final String uri;
  private final String signingAlgorithm = "HmacSHA512";
  private final String hashingAlgorithm = "SHA-512";
  private Headers.Builder headers;
  private SortedMap<String, Object> params = new TreeMap<String, Object>();
  protected int sigVersion = 5;
  private Random random = new Random();
  private OkHttpClient httpClient;
  private SortedMap<String, String> additionalDuoHeaders = new TreeMap<String, String>();

  public static SimpleDateFormat RFC_2822_DATE_FORMAT = 
      new SimpleDateFormat("EEE', 'dd' 'MMM' 'yyyy' 'HH:mm:ss' 'Z", Locale.US);

  public static MediaType FORM_ENCODED = MediaType.parse("application/x-www-form-urlencoded");
  public static MediaType JSON_ENCODED = MediaType.parse("application/json");

  private static final String[] DEFAULT_CA_CERTS = {
      //Source URL: https://www.amazontrust.com/repository/AmazonRootCA1.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Amazon Root CA 1,O=Amazon,C=US
      //Issuer: CN=Amazon Root CA 1,O=Amazon,C=US
      //Expiration Date: 2038-01-17 00:00:00
      //Serial Number: 66C9FCF99BF8C0A39E2F0788A43E696365BCA
      //SHA256 Fingerprint: 8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e
      "sha256/++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=",
      //Source URL: https://www.amazontrust.com/repository/AmazonRootCA2.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Amazon Root CA 2,O=Amazon,C=US
      //Issuer: CN=Amazon Root CA 2,O=Amazon,C=US
      //Expiration Date: 2040-05-26 00:00:00
      //Serial Number: 66C9FD29635869F0A0FE58678F85B26BB8A37
      //SHA256 Fingerprint: 1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4
      "sha256/f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE=",
      //Source URL: https://www.amazontrust.com/repository/AmazonRootCA3.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Amazon Root CA 3,O=Amazon,C=US
      //Issuer: CN=Amazon Root CA 3,O=Amazon,C=US
      //Expiration Date: 2040-05-26 00:00:00
      //Serial Number: 66C9FD5749736663F3B0B9AD9E89E7603F24A
      //SHA256 Fingerprint: 18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4
      "sha256/NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k=",
      //Source URL: https://www.amazontrust.com/repository/AmazonRootCA4.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Amazon Root CA 4,O=Amazon,C=US
      //Issuer: CN=Amazon Root CA 4,O=Amazon,C=US
      //Expiration Date: 2040-05-26 00:00:00
      //Serial Number: 66C9FD7C1BB104C2943E5717B7B2CC81AC10E
      //SHA256 Fingerprint: e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092
      "sha256/9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U=",
      //Source URL: https://www.amazontrust.com/repository/SFSRootCAG2.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Starfield Services Root Certificate Authority - G2,
      // O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
      //Issuer: CN=Starfield Services Root Certificate Authority - G2,
      // O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
      //Expiration Date: 2037-12-31 23:59:59
      //Serial Number: 0
      //SHA256 Fingerprint: 568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5
      "sha256/KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=",
      //Source URL: https://cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
      //Issuer: CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
      //Expiration Date: 2031-11-10 00:00:00
      //Serial Number: 2AC5C266A0B409B8F0B79F2AE462577
      //SHA256 Fingerprint: 7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
      "sha256/WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
      //Source URL: https://cacerts.digicert.com/DigiCertTLSECCP384RootG5.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US
      //Issuer: CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US
      //Expiration Date: 2046-01-14 23:59:59
      //Serial Number: 9E09365ACF7D9C8B93E1C0B042A2EF3
      //SHA256 Fingerprint: 018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05
      "sha256/oC+voZLIy4HLE0FVT5wFtxzKKokLDRKY1oNkfJYe+98=",
      //Source URL: https://cacerts.digicert.com/DigiCertTLSRSA4096RootG5.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=DigiCert TLS RSA4096 Root G5,O=DigiCert\, Inc.,C=US
      //Issuer: CN=DigiCert TLS RSA4096 Root G5,O=DigiCert\, Inc.,C=US
      //Expiration Date: 2046-01-14 23:59:59
      //Serial Number: 8F9B478A8FA7EDA6A333789DE7CCF8A
      //SHA256 Fingerprint: 371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75
      "sha256/ape1HIIZ6T5d7GS61YBs3rD4NVvkfnVwELcCRW4Bqv0=",
      //Source URL: https://secure.globalsign.com/cacert/rootr46.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE
      //Issuer: CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE
      //Expiration Date: 2046-03-20 00:00:00
      //Serial Number: 11D2BBB9D723189E405F0A9D2DD0DF2567D1
      //SHA256 Fingerprint: 4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9
      "sha256/rn+WLLnmp9v3uDP7GPqbcaiRdd+UnCMrap73yz3yu/w=",
      //Source URL: https://secure.globalsign.com/cacert/roote46.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=GlobalSign Root E46,O=GlobalSign nv-sa,C=BE
      //Issuer: CN=GlobalSign Root E46,O=GlobalSign nv-sa,C=BE
      //Expiration Date: 2046-03-20 00:00:00
      //Serial Number: 11D2BBBA336ED4BCE62468C50D841D98E843
      //SHA256 Fingerprint: cbb9c44d84b8043e1050ea31a69f514955d7bfd2e2c6b49301019ad61d9f5058
      "sha256/4EoCLOMvTM8sf2BGKHuCijKpCfXnUUR/g/0scfb9gXM=",
      //Source URL: https://i.pki.goog/r2.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=GTS Root R2,O=Google Trust Services LLC,C=US
      //Issuer: CN=GTS Root R2,O=Google Trust Services LLC,C=US
      //Expiration Date: 2036-06-22 00:00:00
      //Serial Number: 203E5AEC58D04251AAB1125AA
      //SHA256 Fingerprint: 8d25cd97229dbf70356bda4eb3cc734031e24cf00fafcfd32dc76eb5841c7ea8
      "sha256/Vfd95BwDeSQo+NUYxVEEIlvkOlWY2SalKK1lPhzOx78=",
      //Source URL: https://i.pki.goog/r4.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=GTS Root R4,O=Google Trust Services LLC,C=US
      //Issuer: CN=GTS Root R4,O=Google Trust Services LLC,C=US
      //Expiration Date: 2036-06-22 00:00:00
      //Serial Number: 203E5C068EF631A9C72905052
      //SHA256 Fingerprint: 349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d
      "sha256/mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
      //Source URL: https://www.identrust.com/file-download/download/public/5718
      //Certificate #1 Details:
      //Original Format: PKCS7-DER
      //Subject: CN=IdenTrust Commercial Root CA 1,O=IdenTrust,C=US
      //Issuer: CN=IdenTrust Commercial Root CA 1,O=IdenTrust,C=US
      //Expiration Date: 2034-01-16 18:12:23
      //Serial Number: A0142800000014523C844B500000002
      //SHA256 Fingerprint: 5d56499be4d2e08bcfcad08a3e38723d50503bde706948e42f55603019e528ae
      "sha256/B+hU8mp8vTiZJ6oEG/7xts0h3RQ4GK2UfcZVqeWH/og=",
      //Source URL: https://www.identrust.com/file-download/download/public/5842
      //Certificate #1 Details:
      //Original Format: PKCS7-PEM
      //Subject: CN=IdenTrust Commercial Root TLS ECC CA 2,O=IdenTrust,C=US
      //Issuer: CN=IdenTrust Commercial Root TLS ECC CA 2,O=IdenTrust,C=US
      //Expiration Date: 2039-04-11 21:11:10
      //Serial Number: 40018ECF000DE911D7447B73E4C1F82E
      //SHA256 Fingerprint: 983d826ba9c87f653ff9e8384c5413e1d59acf19ddc9c98cecae5fdea2ac229c
      "sha256/uu5PB+MS9L3/ffB/PuTG6A+WjsTtTaF52qqjrcHFXRU=",
      //Source URL: https://ssl-ccp.secureserver.net/repository/sfroot-g2.crt
      //Certificate #1 Details:
      //Original Format: PEM
      //Subject: CN=Starfield Root Certificate Authority - G2,
      // O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
      //Issuer: CN=Starfield Root Certificate Authority - G2,
      // O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
      //Expiration Date: 2037-12-31 23:59:59
      //Serial Number: 0
      //SHA256 Fingerprint: 2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5
      "sha256/gI1os/q0iEpflxrOfRBVDXqVoWN3Tz7Dav/7IT++THQ=",
  };

  /**
   * Http constructor.
   * @param inMethod The method for the http request
   * @param inHost   The api host provided by Duo and found in the Duo admin panel
   * @param inUri    The endpoint for the request
   * 
   * @deprecated Use the HttpBuilder instead
   */
  public Http(String inMethod, String inHost, String inUri) {
    this(inMethod, inHost, inUri, DEFAULT_TIMEOUT_SECS);
  }

  /**
   * Http constructor.
   * @param inMethod The method for the http request
   * @param inHost   The api host provided by Duo and found in the Duo admin panel
   * @param inUri    The endpoint for the request
   * @param timeout  The timeout for the http request
   * 
   * @deprecated Use the HttpBuilder instead
   */
  protected Http(String inMethod, String inHost, String inUri, int timeout) {
    method = inMethod.toUpperCase();
    host = inHost;
    uri = inUri;

    headers = new Headers.Builder();
    headers.add("Host", host);
    headers.add("user-agent", UserAgentString);

    CertificatePinner pinner = Util.createPinner(host, DEFAULT_CA_CERTS);

    httpClient = new OkHttpClient.Builder()
        .connectTimeout(timeout, TimeUnit.SECONDS)
        .writeTimeout(timeout, TimeUnit.SECONDS)
        .readTimeout(timeout, TimeUnit.SECONDS)
        .certificatePinner(pinner)
        .build();
  }

  /**
   * Executes JSON request.
   *
   * @return The result of the JSON request
   *
   * @throws Exception If the result was not OK
   */
  public Object executeJSONRequest() throws Exception {
    JSONObject result = new JSONObject(executeRequestRaw());
    if (!result.getString("stat").equals("OK")) {
      throw new Exception("Duo error code ("
          + result.get("code").toString()
          + "): "
          + result.getString("message"));
    }
    return result;
  }

  public String executeRequestRaw() throws Exception {
    Response response = executeHttpRequest();
    return response.body().string();
  }

  /**
   * Creates and executes a HTTP request.
   *
   * @return The result of the HTTP request
   *
   * @throws UnsupportedEncodingException For http methods that are not supported
   */
  public Response executeHttpRequest() throws Exception {
    String url = "https://" + host + uri;
    String queryString = canonQueryString();
    String jsonBody = canonJSONBody();
    RequestBody requestBody;
    if (sigVersion == 1 || sigVersion == 2) {
      requestBody = RequestBody.create(queryString, FORM_ENCODED);
    } else if (sigVersion == 5) {
      if ("POST".equals(method) || "PUT".equals(method)) {
        requestBody = RequestBody.create(jsonBody, JSON_ENCODED);
      } else {
        requestBody = null;
      }
    } else {
      throw new UnsupportedOperationException("Unsupported signature version: " + sigVersion);
    }

    Request.Builder requestBuilder = new Request.Builder();
    if (method.equals("POST")) {
      requestBuilder.post(requestBody);
    } else if (method.equals("PUT")) {
      requestBuilder.put(requestBody);
    } else if (method.equals("GET")) {
      if (queryString.length() > 0) {
        url += "?" + queryString;
      }
      requestBuilder.get();
    } else if (method.equals("DELETE")) {
      if (queryString.length() > 0) {
        url += "?" + queryString;
      }
      requestBuilder.delete();
    } else {
      throw new UnsupportedOperationException("Unsupported method: " + method);
    }

    // finish and execute request
    Request request = requestBuilder.headers(headers.build()).url(url).build();
    return executeRequest(request);
  }

  public Object executeRequest() throws Exception {
    JSONObject result = (JSONObject) executeJSONRequest();
    return result.get("response");
  }

  private Response executeRequest(Request request) throws Exception {
    long backoffMs = INITIAL_BACKOFF_MS;
    while (true) {
      Response response = httpClient.newCall(request).execute();
      if (response.code() != RATE_LIMIT_ERROR_CODE || backoffMs > MAX_BACKOFF_MS) {
        return response;
      }

      sleep(backoffMs + nextRandomInt(1000));
      backoffMs *= BACKOFF_FACTOR;
    }
  }

  protected void sleep(long ms) throws Exception {
    Thread.sleep(ms);
  }

  public void signRequest(String ikey, String skey)
      throws UnsupportedEncodingException {
    signRequest(ikey, skey, sigVersion);
  }

  /**
   * Signs Duo request.
   *
   * @param ikey         Integration key provided by Duo and found in the admin
   *                     panel
   * @param skey         Secret key provided by Duo and found in the admin panel
   * @param inSigVersion The version of signature used
   *
   * @throws UnsupportedEncodingException For unsupported encodings
   */
  public void signRequest(String ikey, String skey, int inSigVersion)
      throws UnsupportedEncodingException {
    int[] availableSigVersion = { 1, 2, 5 };

    if (Arrays.stream(availableSigVersion).anyMatch(i -> i == inSigVersion)) {
      sigVersion = inSigVersion;
    }
    String date = formatDate(new Date());
    String canon = canonRequest(date, sigVersion);
    String sig = signHMAC(skey, canon);

    String auth = ikey + ":" + sig;
    String header = "Basic " + Base64.encodeBytes(auth.getBytes());
    addHeader("Authorization", header);
    if (sigVersion == 2 || sigVersion == 5) {
      addHeader("Date", date);
    }
  }

  protected String signHMAC(String skey, String msg) {
    try {
      byte[] sigBytes = Util.hmac(signingAlgorithm,
          skey.getBytes(),
          msg.getBytes());
      String sig = Util.bytes_to_hex(sigBytes);
      return sig;
    } catch (Exception e) {
      return "";
    }
  }

  private String formatDate(Date date) {
    // Could use ThreadLocal or a pool of format objects instead
    // depending on the needs of the application.
    synchronized (RFC_2822_DATE_FORMAT) {
      return RFC_2822_DATE_FORMAT.format(date);
    }
  }

  public void addHeader(String name, String value) {
    headers.add(name, value);
  }

  public void addParam(String name, String value) {
    params.put(name, value);
  }

  public void addParam(String name, Integer value) {
    params.put(name, value);
  }

  public void addParam(String name, JSONObject value) {
    params.put(name, value);
  }

  public void addParam(String name, List<Object> value) {
    params.put(name, value);
  }

  public void addAdditionalDuoHeader(Map<String, String> inAdditionalDuoHeaders) {
    additionalDuoHeaders.putAll(inAdditionalDuoHeaders);
  }

  /**
   * Creates a new proxy.
   *
   * @param host The proxy host
   * @param port The port of the proxy
   */
  public void setProxy(String host, int port) {
    Proxy httpProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    httpClient = httpClient.newBuilder().proxy(httpProxy).build();
  }

  /**
   * Use custom CA certificates for certificate pinning.
   *
   * @param customCaCerts The CA certificates to pin
   */
  public void useCustomCertificates(String[] customCaCerts) {
    CertificatePinner pinner = Util.createPinner(host, customCaCerts);
    httpClient = httpClient.newBuilder().certificatePinner(pinner).build();
  }

  protected String canonRequest(String date, int sigVersion)
      throws UnsupportedEncodingException {
    String canon = "";
    String canonParam;
    String canonBody;
    if (sigVersion == 1) {
      canon += method.toUpperCase() + "\n";
      canon += host.toLowerCase() + "\n";
      canon += uri + "\n";
      canon += canonQueryString();
    } else if (sigVersion == 2) {
      canon += date + "\n";
      canon += method.toUpperCase() + "\n";
      canon += host.toLowerCase() + "\n";
      canon += uri + "\n";
      canon += canonQueryString();
    } else if (sigVersion == 5) {
      canon += date + "\n";
      canon += method.toUpperCase() + "\n";
      canon += host.toLowerCase() + "\n";
      canon += uri + "\n";
      if ("POST".equals(method) || "PUT".equals(method)) {
        canonParam = "\n";
        canonBody = Util.bytes_to_hex(Util.hash(hashingAlgorithm, canonJSONBody()));
      } else {
        canonParam = canonQueryString() + "\n";
        canonBody = Util.bytes_to_hex(Util.hash(hashingAlgorithm, ""));
      }
      canon += canonParam;
      canon += canonBody + "\n";
      canon += Util.bytes_to_hex(Util.hash(hashingAlgorithm, canonXDuoHeaders()));
    }

    return canon;
  }

  private String canonQueryString()
      throws UnsupportedEncodingException {
    ArrayList<String> args = new ArrayList<String>();

    for (String key : params.keySet()) {
      String name = URLEncoder
          .encode(key, "UTF-8")
          .replace("+", "%20")
          .replace("*", "%2A")
          .replace("%7E", "~");
      String value = URLEncoder
          .encode(params.get(key).toString(), "UTF-8")
          .replace("+", "%20")
          .replace("*", "%2A")
          .replace("%7E", "~");
      args.add(name + "=" + value);
    }

    return Util.join(args.toArray(), "&");
  }

  private String canonJSONBody() {
    JSONObject jsonBody = new JSONObject(params);
    return jsonBody.toString();
  }

  private String canonXDuoHeaders() {
    List<String> canonList = new ArrayList<>();
    for (String name : additionalDuoHeaders.keySet()) {
      String value = additionalDuoHeaders.get(name);
      canonList.add(name + Character.MIN_VALUE + value);
      headers.add(name, value);
    }
    return Util.join(canonList.toArray(), String.valueOf(Character.MIN_VALUE));
  }

  public int nextRandomInt(int bound) {
    return random.nextInt(bound);
  }

  public static class HttpBuilder extends ClientBuilder<Http> {
    /**
     * Builder entry point.
     *
     * @param method the HTTP method to use
     * @param host   the Duo host
     * @param uri    the API endpoint for the request
     */
    protected HttpBuilder(String method, String host, String uri) {
      super(method, host, uri);
    }

    @Override
    protected Http createClient(String method, String host, String uri, int timeout) {
      return new Http(method, host, uri, timeout);
    }
  }

  /**
   * Builder for an Http client object.
   */
  protected abstract static class ClientBuilder<T extends Http> {
    private final String method;
    private final String host;
    private final String uri;

    private int timeout = DEFAULT_TIMEOUT_SECS;
    private String[] caCerts = null;
    private SortedMap<String, String> additionalDuoHeaders = new TreeMap<String, String>();
    private Map<String, String> headers = new HashMap<String, String>();

    /**
     * Builder entry point.
     *
     * @param method the HTTP method to use
     * @param host   the Duo host
     * @param uri    the API endpoint for the request
     */
    public ClientBuilder(String method, String host, String uri) {
      this.method = method;
      this.host = host;
      this.uri = uri;
    }

    /**
     * Set a custom timeout for HTTP calls.
     *
     * @param timeout the timeout to use
     * @return the Builder
     */
    public ClientBuilder<T> useTimeout(int timeout) {
      this.timeout = timeout;

      return this;
    }

    /**
     * Provide custom CA certificates for certificate pinning.
     *
     * @param customCaCerts The CA certificates to pin to
     * @return the Builder
     */
    public ClientBuilder<T> useCustomCertificates(String[] customCaCerts) {
      this.caCerts = customCaCerts;

      return this;
    }

    /**
     * Set additional x-duo header for the HTTP client.
     *
     * @param name  Header's name
     * @param value Header's value
     * @return the Builder
     */
    public ClientBuilder<T> addAdditionalDuoHeader(String name, String value) 
        throws IllegalArgumentException {
      validateXDuoHeader(name, value);
      this.additionalDuoHeaders.put(name.toLowerCase(), value);
      return this;

    }

    /**
     * Add header for the HTTP client.
     *
     * @param name  Header's name
     * @param value Header's value
     * @return the Builder
     */
    public ClientBuilder<T> addHeader(String name, String value) {
      this.headers.put(name, value);
      return this;
    }

    /**
     * Build the HTTP client object based on the builder options.
     *
     * @return the specified Http client object
     */
    public T build() {
      T duoClient = createClient(method, host, uri, timeout);
      if (caCerts != null) {
        duoClient.useCustomCertificates(caCerts);
      }
      if (additionalDuoHeaders != null) {
        duoClient.addAdditionalDuoHeader(additionalDuoHeaders);
      }
      if (headers != null) {
        for (String name : headers.keySet()) {
          String value = headers.get(name);
          duoClient.addHeader(name, value);
        }
      }

      return duoClient;
    }

    protected abstract T createClient(String method, String host, String uri, int timeout);

    private void validateXDuoHeader(String name, String value) throws IllegalArgumentException {
      if (name == null || name.length() == 0) {
        throw new IllegalArgumentException("Not allowed 'Null' or empty header name");
      } else if (value == null || value.length() == 0) {
        throw new IllegalArgumentException("Not allowed 'Null' or empty header value");
      } else if (!name.toLowerCase().startsWith("x-duo-")) {
        throw new IllegalArgumentException("Additional headers must start with \'X-Duo-\'");
      } else if (additionalDuoHeaders.containsKey(name)) {
        throw new IllegalArgumentException("Duplicate header passed, header=" + name);
      }
    }
  }
}
