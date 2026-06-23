package com.duosecurity.client;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.Set;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import org.junit.Test;

public class HttpDisableCaPinningTest {

  private OkHttpClient getHttpClient(Http http) throws Exception {
    Field httpClientField = Http.class.getDeclaredField("httpClient");
    httpClientField.setAccessible(true);
    return (OkHttpClient) httpClientField.get(http);
  }

  @SuppressWarnings("unchecked")
  private Set<?> getPins(CertificatePinner pinner) throws Exception {
    Field pinsField = CertificatePinner.class.getDeclaredField("pins");
    pinsField.setAccessible(true);
    return (Set<?>) pinsField.get(pinner);
  }

  @Test
  public void testDisableCaPinning_removesPin() throws Exception {
    Http http = new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .disableCaPinning()
        .build();

    OkHttpClient client = getHttpClient(http);
    Set<?> pins = getPins(client.certificatePinner());
    assertTrue("Pins should be empty when CA pinning is disabled", pins.isEmpty());
  }

  @Test
  public void testDefaultBuilder_hasPinning() throws Exception {
    Http http = new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .build();

    OkHttpClient client = getHttpClient(http);
    Set<?> pins = getPins(client.certificatePinner());
    assertFalse("Pins should not be empty by default", pins.isEmpty());
  }

  @Test(expected = IllegalStateException.class)
  public void testDisableAndCustomCerts_throws() {
    new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .disableCaPinning()
        .useCustomCertificates(new String[]{"sha256/test"})
        .build();
  }

  @Test(expected = IllegalStateException.class)
  public void testCustomCertsAndDisable_throws() {
    new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .useCustomCertificates(new String[]{"sha256/test"})
        .disableCaPinning()
        .build();
  }
}
