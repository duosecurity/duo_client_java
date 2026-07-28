package com.duosecurity.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import okhttp3.Headers;
import org.junit.Test;

public class HttpUserAgentTest {

  private Headers getHeaders(Http http) throws Exception {
    Field headersField = Http.class.getDeclaredField("headers");
    headersField.setAccessible(true);
    Headers.Builder headersBuilder = (Headers.Builder) headersField.get(http);
    return headersBuilder.build();
  }

  private String getUserAgent(Http http) throws Exception {
    return getHeaders(http).get("user-agent");
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

  @Test
  public void testCustomUserAgentHeader_isReplacedNotDuplicated() throws Exception {
    Http http = new Http.HttpBuilder("GET", "api-host.duosecurity.com", "/auth/v2/check")
        .addHeader("user-agent", "MyApp/1.0")
        .build();

    Headers headers = getHeaders(http);
    assertEquals(1, headers.values("user-agent").size());
    assertEquals(String.format("%s ca_bundle/1.0 (ca_pinning=enabled)", Http.UserAgentString),
        headers.get("user-agent"));
  }
}
