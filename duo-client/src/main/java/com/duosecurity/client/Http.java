package com.duosecurity.client;

import okhttp3.*;

import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

public class Http {
  public static final int BACKOFF_FACTOR = 2;
  public static final int INITIAL_BACKOFF_MS = 1000;
  public static final int MAX_BACKOFF_MS = 32000;
  public static final int DEFAULT_TIMEOUT_SECS = 60;
  private static final int RATE_LIMIT_ERROR_CODE = 429;

  public static final String UserAgentString = "Duo API Java/0.5.2-SNAPSHOT";

  private final String method;
  private final String host;
  private final String uri;
  private final String signingAlgorithm = "HmacSHA512";
  private Headers.Builder headers;
  Map<String, String> params = new HashMap<String, String>();
  private Random random = new Random();
  private OkHttpClient httpClient;
  private int sigVersion = 2;

  public static SimpleDateFormat RFC_2822_DATE_FORMAT
      = new SimpleDateFormat("EEE', 'dd' 'MMM' 'yyyy' 'HH:mm:ss' 'Z", Locale.US);

  public static MediaType FORM_ENCODED = MediaType.parse("application/x-www-form-urlencoded");

  private static final String[] DEFAULT_CA_CERTS = {
      //C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA
      "sha256/I/Lt/z7ekCWanjD0Cvj5EqXls2lOaThEA0H2Bg4BT/o=",
      //C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA
      "sha256/r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=",
      //C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA
      "sha256/WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
      //C=US, O=SecureTrust Corporation, CN=SecureTrust CA
      "sha256/dykHF2FLJfEpZOvbOLX4PKrcD2w2sHd/iA/G3uHTOcw=",
      //C=US, O=SecureTrust Corporation, CN=Secure Global CA
      "sha256/JZaQTcTWma4gws703OR/KFk313RkrDcHRvUt6na6DCg=",
      //C=US, O=Amazon, CN=Amazon Root CA 1
      "sha256/++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=",
      //C=US, O=Amazon, CN=Amazon Root CA 2
      "sha256/f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE=",
      //C=US, O=Amazon, CN=Amazon Root CA 3
      "sha256/NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k=",
      //C=US, O=Amazon, CN=Amazon Root CA 4
      "sha256/9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U=",
      //C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 2
      "sha256/j9ESw8g3DxR9XM06fYZeuN1UB4O6xp/GAIjjdD/zM3g="
  };

  /**
   * @deprecated Use the HttpBuilder instead
   */
  public Http(String inMethod, String inHost, String inUri) {
    this(inMethod, inHost, inUri, DEFAULT_TIMEOUT_SECS);
  }

  /**
   * Http constructor.
   *
   * @deprecated Use the HttpBuilder instead
   * @param inMethod    The method for the http request
   * @param inHost      The api host provided by Duo and found in the Duo admin panel
   * @param inUri       The endpoint for the request
   * @param timeout     The timeout for the http request
   */
  public Http(String inMethod, String inHost, String inUri, int timeout) {
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
   * @return            The result of the JSON request
   *
   * @throws Exception  If the result was not OK
   */
  public Object executeJSONRequest() throws Exception {
    JSONObject result = new JSONObject(executeRequestRaw());
    if (! result.getString("stat").equals("OK")) {
      throw new Exception("Duo error code ("
                          + result.getInt("code")
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
   * @return                              The result of the HTTP request
   *
   * @throws UnsupportedEncodingException For http methods that are not supported
   */
  public Response executeHttpRequest() throws Exception {
    String url = "https://" + host + uri;
    String queryString = canonQueryString();
    RequestBody requestBody;
    if (sigVersion == 1 | sigVersion == 2){
      requestBody = RequestBody.create(queryString, FORM_ENCODED);
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
    JSONObject result = (JSONObject)executeJSONRequest();
    return result.get("response");
  }

  private Response executeRequest(Request request) throws Exception {
    long backoffMs = INITIAL_BACKOFF_MS;
    while (true) {
      Response response = httpClient.newCall(request).execute();
      if (response.code() != RATE_LIMIT_ERROR_CODE || backoffMs > MAX_BACKOFF_MS) {
        return response;
      }

      sleep(backoffMs + random.nextInt(1000));
      backoffMs *= BACKOFF_FACTOR;
    }
  }

  protected void sleep(long ms) throws Exception {
    Thread.sleep(ms);
  }

  public void signRequest(String ikey, String skey)
      throws UnsupportedEncodingException {
    signRequest(ikey, skey, 2);
  }

  /**
   * Signs Duo request.
   *
   * @param ikey        Integration key provided by Duo and found in the admin panel
   * @param skey        Secret key provided by Duo and found in the admin panel
   * @param sigVersion  The version of signature used
   *
   * @throws UnsupportedEncodingException For unsupported encodings
   */
  public void signRequest(String ikey, String skey, int inSigVersion)
      throws UnsupportedEncodingException {
    int[] availableSigVersion = {1, 2};

    if (Arrays.stream(availableSigVersion).anyMatch(i -> i == inSigVersion)){
      sigVersion = inSigVersion;
    }

    String date = formatDate(new Date());
    String canon = canonRequest(date, sigVersion);
    String sig = signHMAC(skey, canon);

    String auth = ikey + ":" + sig;
    String header = "Basic " + Base64.encodeBytes(auth.getBytes());
    addHeader("Authorization", header);
    if (sigVersion == 2) {
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

  /**
   * Creates a new proxy.
   *
   * @param host    The proxy host
   * @param port    The port of the proxy
   */
  public void setProxy(String host, int port) {
    Proxy httpProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    httpClient = httpClient.newBuilder().proxy(httpProxy).build();
  }

  /**
   * Use custom CA certificates for certificate pinning
   *
   * @param customCaCerts   The CA certificates to pin
   */
  public void useCustomCertificates(String[] customCaCerts) {
    CertificatePinner pinner = Util.createPinner(host, customCaCerts);
    httpClient = httpClient.newBuilder().certificatePinner(pinner).build();
  }

  protected String canonRequest(String date, int sigVersion)
      throws UnsupportedEncodingException {
    String canon = "";
    if (sigVersion == 1) {
      canon += method.toUpperCase() + System.lineSeparator();
      canon += host.toLowerCase() + System.lineSeparator();
      canon += uri + System.lineSeparator();
      canon += canonQueryString();
    }
    else if (sigVersion == 2) {
      canon += date + System.lineSeparator();
      canon += method.toUpperCase() + System.lineSeparator();
      canon += host.toLowerCase() + System.lineSeparator();
      canon += uri + System.lineSeparator();
      canon += canonQueryString();
    }

    return canon;
  }

  private String canonQueryString()
      throws UnsupportedEncodingException {
    ArrayList<String> args = new ArrayList<String>();
    ArrayList<String> keys = new ArrayList<String>();

    for (String key : params.keySet()) {
      keys.add(key);
    }

    Collections.sort(keys);

    for (String key : keys) {
      String name = URLEncoder
          .encode(key, "UTF-8")
          .replace("+", "%20")
          .replace("*", "%2A")
          .replace("%7E", "~");
      String value = URLEncoder
          .encode(params.get(key), "UTF-8")
          .replace("+", "%20")
          .replace("*", "%2A")
          .replace("%7E", "~");
      args.add(name + "=" + value);
    }

    return Util.join(args.toArray(), "&");
  }

  /**
   * Builder for an Http client object
   */
  public static class HttpBuilder {
    private final String method;
    private final String host;
    private final String uri;

    private int timeout = DEFAULT_TIMEOUT_SECS;
    private String[] caCerts = null;

    /**
     * Builder entry point
     *
     * @param method: the HTTP method to use
     * @param host: the Duo host
     * @param uri: the API endpoint for the request
     */
    public HttpBuilder(String method, String host, String uri) {
      this.method = method;
      this.host = host;
      this.uri = uri;
    }

    /**
     * Set a custom timeout for HTTP calls
     *
     * @param timeout: the timeout to use
     * @return the Builder
     */
    public HttpBuilder useTimeout(int timeout) {
      this.timeout = timeout;

      return this;
    }

    /**
     * Provide custom CA certificates for certificate pinning
     *
     * @param customCaCerts   The CA certificates to pin to
     * @return the Builder
     */
    public HttpBuilder useCustomCertificates(String[] customCaCerts) {
      this.caCerts = customCaCerts;

      return this;
    }

    /**
     * Build the HTTP client object based on the builder options
     *
     * @return the specified Http client object
     */
    public Http build() {
      Http duoClient = new Http(method, host, uri, timeout);
      if (caCerts != null) {
        duoClient.useCustomCertificates(caCerts);
      }

      return duoClient;
    }
  }
}
