package com.duosecurity.client;

import okhttp3.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

@RunWith(MockitoJUnitRunner.class)
public class HttpRateLimitRetryTest {
    @Mock
    private OkHttpClient httpClient;

    private Http http;

    private final int RANDOM_INT = 234;

    @Before
    public void before() throws Exception {
        http = new Accounts.AccountsBuilder("GET", "example.test", "/foo/bar").build();
        http = Mockito.spy(http);

        Field httpClientField = Http.class.getDeclaredField("httpClient");
        httpClientField.setAccessible(true);
        httpClientField.set(http, httpClient);

        Mockito.when(http.nextRandomInt(1000)).thenReturn(RANDOM_INT);
        Mockito.doNothing().when(http).sleep(Mockito.any(Long.class));
    }

    @Test
    public void testSingleRateLimitRetry() throws Exception {
        final List<Response> responses = new ArrayList<Response>();
        final List<Call> calls = new ArrayList<Call>();

        Mockito.when(httpClient.newCall(Mockito.any(Request.class))).thenAnswer(new Answer<Call>() {
            @Override
            public Call answer(InvocationOnMock invocationOnMock) throws Throwable {
                Call call = Mockito.mock(Call.class);
                calls.add(call);

                Response resp = new Response.Builder()
                        .protocol(Protocol.HTTP_2)
                        .code(responses.isEmpty() ? 429 : 200) // Fail on first req, succeed after
                        .request((Request) invocationOnMock.getArguments()[0])
                        .message("HTTP 429 or 200")
                        .build();
                responses.add(resp);
                Mockito.when(call.execute()).thenReturn(resp);

                return call;
            }
        });

        Response actualRes = http.executeHttpRequest();
        assertEquals(2, responses.size());
        assertEquals(2, calls.size());
        assertEquals(200, actualRes.code());

        // Verify the calls to sleep on failures
        ArgumentCaptor<Long> sleepCapture = ArgumentCaptor.forClass(Long.class);
        Mockito.verify(http).sleep(sleepCapture.capture());
        List<Long> sleepTimes = sleepCapture.getAllValues();
        assertEquals(1000L + RANDOM_INT, (long) sleepTimes.get(0));
    }

    @Test
    public void testRepeatRetryAfterRateLimit() throws Exception {
        final List<Response> responses = new ArrayList<Response>();
        final List<Call> calls = new ArrayList<Call>();

        Mockito.when(httpClient.newCall(Mockito.any(Request.class))).thenAnswer(new Answer<Call>() {
            @Override
            public Call answer(InvocationOnMock invocationOnMock) throws Throwable {
                Call call = Mockito.mock(Call.class);
                calls.add(call);

                Response resp = new Response.Builder()
                        .protocol(Protocol.HTTP_2)
                        .code(429)
                        .request((Request) invocationOnMock.getArguments()[0])
                        .message("HTTP 429")
                        .build();
                responses.add(resp);
                Mockito.when(call.execute()).thenReturn(resp);

                return call;
            }
        });

        // It will take 7 total requests before the client hits the max backoff.
        // Once we hit the max backoff, we just assume the request will never work
        // and we return the rate limited response.
        int totalRequestCount = 7;
        int requestRetryCount = totalRequestCount - 1;

        Response actualRes = http.executeHttpRequest();
        assertEquals(totalRequestCount, responses.size());
        assertEquals(totalRequestCount, calls.size());
        assertEquals(responses.get(responses.size() - 1), actualRes);

        // Verify execution of the new calls
        for (Call call: calls) {
            Mockito.verify(call).execute();
        }

        // Verify the calls to sleep on failures. We will sleep before every retry,
        // which means there will be one less sleep then the number of requests made
        ArgumentCaptor<Long> sleepCapture = ArgumentCaptor.forClass(Long.class);
        Mockito.verify(http, Mockito.times(requestRetryCount))
                .sleep(sleepCapture.capture());
        List<Long> sleepTimes = sleepCapture.getAllValues();
        assertEquals(1000L + RANDOM_INT, (long) sleepTimes.get(0));
        assertEquals(2000L + RANDOM_INT, (long) sleepTimes.get(1));
        assertEquals(4000L + RANDOM_INT, (long) sleepTimes.get(2));
        assertEquals(8000L + RANDOM_INT, (long) sleepTimes.get(3));
        assertEquals(16000L + RANDOM_INT, (long) sleepTimes.get(4));
        assertEquals(32000L + RANDOM_INT, (long) sleepTimes.get(5));
    }
}
