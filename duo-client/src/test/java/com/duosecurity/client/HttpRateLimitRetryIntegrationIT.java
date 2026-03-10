package com.duosecurity.client;

import okhttp3.OkHttpClient;
import okhttp3.Response;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;

import static org.junit.Assert.assertEquals;

public class HttpRateLimitRetryIntegrationIT {

    private MockWebServer server;
    private HandshakeCertificates clientCerts;

    @Before
    public void setUp() throws Exception {
        HeldCertificate serverCert = new HeldCertificate.Builder()
                .addSubjectAlternativeName("localhost")
                .build();

        HandshakeCertificates serverCerts = new HandshakeCertificates.Builder()
                .heldCertificate(serverCert)
                .build();

        clientCerts = new HandshakeCertificates.Builder()
                .addTrustedCertificate(serverCert.certificate())
                .build();

        server = new MockWebServer();
        server.useHttps(serverCerts.sslSocketFactory(), false);
        server.start();
    }

    @After
    public void tearDown() throws Exception {
        server.shutdown();
    }

    /**
     * Builds an Http spy pointing at the MockWebServer, with sleep() stubbed out to avoid real
     * delays and the OkHttpClient replaced with one that trusts the test certificate.
     *
     * <p>The builder must be constructed with host "localhost" (no port) so that CertificatePinner
     * accepts the pattern. This method then sets the real host (with port) and replaces the
     * OkHttpClient via reflection before the spy is used.
     */
    private Http buildSpyHttp(Http.ClientBuilder<Http> builder) throws Exception {
        Http spy = Mockito.spy(builder.build());
        Mockito.doNothing().when(spy).sleep(Mockito.any(Long.class));

        // Point the host at the MockWebServer port (CertificatePinner rejects host:port patterns,
        // so the builder uses "localhost" and we fix it here after construction).
        Field hostField = Http.class.getDeclaredField("host");
        hostField.setAccessible(true);
        hostField.set(spy, "localhost:" + server.getPort());

        // Replace the OkHttpClient with one configured to trust the test certificate
        OkHttpClient testClient = new OkHttpClient.Builder()
                .sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager())
                .build();

        Field httpClientField = Http.class.getDeclaredField("httpClient");
        httpClientField.setAccessible(true);
        httpClientField.set(spy, testClient);

        return spy;
    }

    private Http.HttpBuilder defaultBuilder() {
        // Use "localhost" without a port — CertificatePinner rejects host:port patterns.
        // buildSpyHttp sets the real host (with port) via reflection after construction.
        return new Http.HttpBuilder("GET", "localhost", "/foo/bar");
    }

    @Test
    public void testSingleRateLimitRetry() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(429));
        server.enqueue(new MockResponse().setResponseCode(200));

        Http http = buildSpyHttp(defaultBuilder());
        Response response = http.executeHttpRequest();

        assertEquals(200, response.code());
        assertEquals(2, server.getRequestCount());
        Mockito.verify(http, Mockito.times(1)).sleep(Mockito.any(Long.class));
    }

    @Test
    public void testRateLimitExhaustsDefaultMaxBackoff() throws Exception {
        // Enqueue more responses than will ever be consumed
        for (int i = 0; i < 10; i++) {
            server.enqueue(new MockResponse().setResponseCode(429));
        }

        Http http = buildSpyHttp(defaultBuilder());
        Response response = http.executeHttpRequest();

        assertEquals(429, response.code());
        // Default max backoff (32s): sleeps at 1s, 2s, 4s, 8s, 16s, 32s = 6 sleeps, 7 total requests
        assertEquals(7, server.getRequestCount());
        Mockito.verify(http, Mockito.times(6)).sleep(Mockito.any(Long.class));
    }

    @Test
    public void testCustomMaxBackoffLimitsRetries() throws Exception {
        for (int i = 0; i < 10; i++) {
            server.enqueue(new MockResponse().setResponseCode(429));
        }

        Http http = buildSpyHttp(defaultBuilder().useMaxBackoffMs(4000));
        Response response = http.executeHttpRequest();

        assertEquals(429, response.code());
        // maxBackoff=4000: sleeps at 1s, 2s, 4s = 3 sleeps, 4 total requests (next would be 8s > 4s)
        assertEquals(4, server.getRequestCount());
        Mockito.verify(http, Mockito.times(3)).sleep(Mockito.any(Long.class));
    }

    @Test
    public void testMaxBackoffZeroDisablesRetry() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(429));

        Http http = buildSpyHttp(defaultBuilder().useMaxBackoffMs(0));
        Response response = http.executeHttpRequest();

        assertEquals(429, response.code());
        assertEquals(1, server.getRequestCount());
        Mockito.verify(http, Mockito.never()).sleep(Mockito.any(Long.class));
    }
}
