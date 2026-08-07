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
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
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

  private static final String CA_BUNDLE_VERSION = "1.0";
  public static final String UserAgentString = "Duo API Java/0.8.1-SNAPSHOT";

  private final String method;
  private final String host;
  private final String uri;
  private final String signingAlgorithm = "HmacSHA512";
  private final String hashingAlgorithm = "SHA-512";
  private Headers.Builder headers;
  private SortedMap<String, Object> params = new TreeMap<String, Object>();
  protected int sigVersion = 5;
  private long maxBackoffMs = MAX_BACKOFF_MS;
  private Random random = new Random();
  private OkHttpClient httpClient;
  private SortedMap<String, String> additionalDuoHeaders = new TreeMap<String, String>();

  public static SimpleDateFormat RFC_2822_DATE_FORMAT = 
      new SimpleDateFormat("EEE', 'dd' 'MMM' 'yyyy' 'HH:mm:ss' 'Z", Locale.US);

  public static MediaType FORM_ENCODED = MediaType.parse("application/x-www-form-urlencoded");
  public static MediaType JSON_ENCODED = MediaType.parse("application/json");


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
    headers.add("user-agent", String.format("%s ca_bundle/%s (ca_pinning=%s)",
        UserAgentString, CA_BUNDLE_VERSION, "enabled"));

    TrustManagerFactory tmf = CertificateUtils.createDefaultTrustManagerFactory();
    SSLSocketFactory sslFactory = CertificateUtils.createSslSocketFactory(tmf);
    X509TrustManager trustManager = CertificateUtils.getX509TrustManager(tmf);

    httpClient = new OkHttpClient.Builder()
        .connectTimeout(timeout, TimeUnit.SECONDS)
        .writeTimeout(timeout, TimeUnit.SECONDS)
        .readTimeout(timeout, TimeUnit.SECONDS)
        .sslSocketFactory(sslFactory, trustManager)
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
      if (response.code() != RATE_LIMIT_ERROR_CODE || backoffMs > maxBackoffMs) {
        return response;
      }

      // Close the 429 response to release the connection back to the pool before retrying
      if (response.body() != null) {
        response.close();
      }
      sleep(backoffMs + nextRandomInt(1000));
      backoffMs *= BACKOFF_FACTOR;
    }
  }

  protected void sleep(long ms) throws Exception {
    Thread.sleep(ms);
  }

  protected void setMaxBackoffMs(long maxBackoffMs) {
    if (maxBackoffMs < 0) {
      throw new IllegalArgumentException("maxBackoffMs must be >= 0");
    }
    this.maxBackoffMs = maxBackoffMs;
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

  void setHeader(String name, String value) {
    headers.set(name, value);
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
   * Use custom CA certificates for the trust store.
   *
   * @param pemContent PEM-encoded CA certificates as a String
   */
  public void useCustomCertificates(String pemContent) {
    TrustManagerFactory tmf = CertificateUtils.createTrustManagerFactory(pemContent);
    SSLSocketFactory sslFactory = CertificateUtils.createSslSocketFactory(tmf);
    X509TrustManager trustManager = CertificateUtils.getX509TrustManager(tmf);
    httpClient = httpClient.newBuilder()
        .sslSocketFactory(sslFactory, trustManager)
        .build();
  }

  /**
   * Disable CA certificate pinning. TLS verification remains active
   * via the OS trust store.
   */
  public void disableCaPinning() {
    TrustManagerFactory tmf = CertificateUtils.getSystemTrustManagerFactory();
    SSLSocketFactory sslFactory = CertificateUtils.createSslSocketFactory(tmf);
    X509TrustManager trustManager = CertificateUtils.getX509TrustManager(tmf);
    httpClient = httpClient.newBuilder()
        .sslSocketFactory(sslFactory, trustManager)
        .build();
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
    private long maxBackoffMs = MAX_BACKOFF_MS;
    private String customCertsContent = null;
    private boolean disableCaPinning = false;
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
     * Set the maximum base backoff time in milliseconds for rate limit (429) retries.
     * When a request receives a 429 response, the client retries with exponential
     * backoff until the base backoff exceeds this threshold. Note that actual sleep
     * time includes up to 1000ms of random jitter on top of the base backoff.
     * Setting to 0 disables retries (as does any value below the initial
     * backoff of 1000ms). Default is 32000ms (32 seconds).
     *
     * <p>Note: When using method chaining from outside this package (e.g. with
     * {@code AuthBuilder} or {@code AdminBuilder}), assign the builder to a variable
     * and call methods separately, then call {@code build()}. This is a known
     * limitation of all {@code ClientBuilder} methods.
     *
     * @param maxBackoffMs the maximum base backoff in milliseconds (must be >= 0)
     * @return the Builder
     * @throws IllegalArgumentException if maxBackoffMs is negative
     */
    public ClientBuilder<T> useMaxBackoffMs(long maxBackoffMs) {
      if (maxBackoffMs < 0) {
        throw new IllegalArgumentException("maxBackoffMs must be >= 0");
      }
      this.maxBackoffMs = maxBackoffMs;

      return this;
    }

    /**
     * Provide custom CA certificates for the trust store.
     *
     * @param pemContent PEM-encoded CA certificates as a String
     * @return the Builder
     */
    public ClientBuilder<T> useCustomCertificates(String pemContent) {
      this.customCertsContent = pemContent;

      return this;
    }

    /**
     * Disable CA certificate pinning. TLS verification remains active
     * via the OS trust store.
     *
     * @return the Builder
     * @throws IllegalStateException if custom certificates have also been set
     */
    public ClientBuilder<T> disableCaPinning() {
      this.disableCaPinning = true;

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
      if (disableCaPinning && customCertsContent != null) {
        throw new IllegalStateException(
            "Cannot both disable CA pinning and provide custom certificates");
      }
      T duoClient = createClient(method, host, uri, timeout);
      duoClient.setMaxBackoffMs(maxBackoffMs);
      if (customCertsContent != null) {
        duoClient.useCustomCertificates(customCertsContent);
      }
      if (disableCaPinning) {
        duoClient.disableCaPinning();
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
      String caPinningStatus = disableCaPinning ? "disabled" : "enabled";
      duoClient.setHeader("user-agent", String.format("%s ca_bundle/%s (ca_pinning=%s)",
          UserAgentString, CA_BUNDLE_VERSION, caPinningStatus));

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
