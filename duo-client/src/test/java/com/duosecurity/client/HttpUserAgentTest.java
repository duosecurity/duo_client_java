package com.duosecurity.client;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import okhttp3.Headers;
import org.junit.Test;

public class HttpUserAgentTest {

  private String getUserAgent(Http http) throws Exception {
    Field headersField = Http.class.getDeclaredField("headers");
    headersField.setAccessible(true);
    Headers.Builder headersBuilder = (Headers.Builder) headersField.get(http);
    return headersBuilder.build().get("user-agent");
  }

  @Test
  public void testDefaultBuilder_includesCaBundleVersion() throws Exception {
    Http http = new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .build();

    String userAgent = getUserAgent(http);
    assertTrue(userAgent.contains("ca_bundle/1.0"));
  }

  @Test
  public void testDefaultBuilder_includesCaPinningEnabled() throws Exception {
    Http http = new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .build();

    String userAgent = getUserAgent(http);
    assertTrue(userAgent.contains("(ca_pinning=enabled)"));
  }

  @Test
  public void testDisableCaPinning_includesCaPinningDisabled() throws Exception {
    Http http = new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .disableCaPinning()
        .build();

    String userAgent = getUserAgent(http);
    assertTrue(userAgent.contains("(ca_pinning=disabled)"));
  }

  @Test
  public void testLegacyConstructor_includesCaBundleAndPinningEnabled() throws Exception {
    Http http = new Http("GET", "api-host.duosecurity.com", "/auth/v2/check");

    String userAgent = getUserAgent(http);
    assertTrue(userAgent.contains("ca_bundle/1.0"));
    assertTrue(userAgent.contains("(ca_pinning=enabled)"));
  }
}
