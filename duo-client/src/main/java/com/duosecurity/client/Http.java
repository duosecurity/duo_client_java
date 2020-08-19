package com.duosecurity.client;

import com.squareup.okhttp.Headers;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
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

  public static final String HmacSHA1 = "HmacSHA1";
  public static final String HmacSHA512 = "HmacSHA512";
  public static final String UserAgentString = "Duo API Java/0.3.0";

  private String method;
  private String host;
  private String uri;
  private String signingAlgorithm;
  private Headers.Builder headers;
  Map<String, String> params = new HashMap<String, String>();
  private Random random = new Random();
  private OkHttpClient httpClient;

  public static SimpleDateFormat RFC_2822_DATE_FORMAT
      = new SimpleDateFormat("EEE', 'dd' 'MMM' 'yyyy' 'HH:mm:ss' 'Z", Locale.US);

  public static MediaType FORM_ENCODED = MediaType.parse("application/x-www-form-urlencoded");

  public Http(String inMethod, String inHost, String inUri) {
    this(inMethod, inHost, inUri, DEFAULT_TIMEOUT_SECS);
  }

  /**
   * Http constructor.
   *
   * @param inMethod    The method for the http request
   * @param inHost      The api host provided by Duo and found in the Duo admin panel
   * @param inUri       The endpoint for the request
   * @param timeout     The timeout for the http request
   */
  public Http(String inMethod, String inHost, String inUri, int timeout) {
    method = inMethod.toUpperCase();
    host = inHost;
    uri = inUri;
    signingAlgorithm = "HmacSHA1";

    headers = new Headers.Builder();
    headers.add("Host", host);
    headers.add("user-agent", UserAgentString);

    httpClient = new OkHttpClient();
    httpClient.setConnectTimeout(timeout, TimeUnit.SECONDS);
    httpClient.setWriteTimeout(timeout, TimeUnit.SECONDS);
    httpClient.setReadTimeout(timeout, TimeUnit.SECONDS);
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
    String queryString = createQueryString();

    Request.Builder builder = new Request.Builder();
    if (method.equals("POST")) {
      builder.post(RequestBody.create(FORM_ENCODED, queryString));
    } else if (method.equals("PUT")) {
      builder.put(RequestBody.create(FORM_ENCODED, queryString));
    } else if (method.equals("GET")) {
      if (queryString.length() > 0) {
        url += "?" + queryString;
      }
      builder.get();
    } else if (method.equals("DELETE")) {
      if (queryString.length() > 0) {
        url += "?" + queryString;
      }
      builder.delete();
    } else {
      throw new UnsupportedOperationException("Unsupported method: " + method);
    }

    // finish and execute request
    Request request = builder.headers(headers.build()).url(url).build();
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
  public void signRequest(String ikey, String skey, int sigVersion)
      throws UnsupportedEncodingException {
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
    this.httpClient.setProxy(
        new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port))
    );
  }

  /**
   * Set Signing Algorithm.
   *
   * @param algorithm   The algorith used for signing
   *
   * @throws NoSuchAlgorithmException For algorithms that are not HmacSHA1 or HmacSHA512
   */
  public void setSigningAlgorithm(String algorithm)
      throws NoSuchAlgorithmException {
    if (algorithm != HmacSHA1 && algorithm != HmacSHA512) {
      throw new NoSuchAlgorithmException(algorithm);
    }
    signingAlgorithm = algorithm;
  }

  protected String canonRequest(String date, int sigVersion)
      throws UnsupportedEncodingException {
    String canon = "";
    if (sigVersion == 2) {
      canon += date + "\n";
    }
    canon += method.toUpperCase() + "\n";
    canon += host.toLowerCase() + "\n";
    canon += uri + "\n";
    canon += createQueryString();

    return canon;
  }

  private String createQueryString()
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
}
