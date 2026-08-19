package com.duosecurity.client;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;

import java.lang.reflect.Field;
import javax.net.ssl.SSLSocketFactory;
import okhttp3.OkHttpClient;
import org.junit.Test;

public class HttpDisableCaPinningTest {

  private OkHttpClient getHttpClient(Http http) throws Exception {
    Field httpClientField = Http.class.getDeclaredField("httpClient");
    httpClientField.setAccessible(true);
    return (OkHttpClient) httpClientField.get(http);
  }

  @Test
  public void testDefaultBuilder_hasCustomSslFactory() throws Exception {
    Http http = new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .build();

    OkHttpClient client = getHttpClient(http);
    SSLSocketFactory factory = client.sslSocketFactory();
    assertNotNull("SSLSocketFactory should not be null", factory);

    // Verify it's not the same instance as a default OkHttpClient would use
    OkHttpClient defaultClient = new OkHttpClient();
    assertNotSame("Should use custom SSL factory instance, not OkHttp default",
        defaultClient.sslSocketFactory(), factory);
  }

  @Test
  public void testDisableCaPinning_usesSystemTrustStore() throws Exception {
    Http http = new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .disableCaPinning()
        .build();

    OkHttpClient client = getHttpClient(http);
    SSLSocketFactory factory = client.sslSocketFactory();
    assertNotNull("SSLSocketFactory should not be null", factory);
  }

  @Test(expected = IllegalStateException.class)
  public void testDisableAndCustomCerts_throws() {
    String pemContent = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
    new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .disableCaPinning()
        .useCustomCertificates(pemContent)
        .build();
  }

  @Test(expected = IllegalStateException.class)
  public void testCustomCertsAndDisable_throws() {
    String pemContent = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
    new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .useCustomCertificates(pemContent)
        .disableCaPinning()
        .build();
  }
}
