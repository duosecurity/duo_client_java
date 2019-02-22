package com.duosecurity.client;

import com.squareup.okhttp.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static junit.framework.Assert.assertEquals;

@RunWith(MockitoJUnitRunner.class)
public class HttpRateLimitRetryTest {
    @Mock
    private OkHttpClient httpClient;
    @Mock
    private Random random;

    private Http http;

    private final int RANDOM_INT = 234;

    @Before
    public void before() throws Exception {
        http = new Http("GET", "example.test", "/foo/bar");
        http = Mockito.spy(http);

        Field randomField = Http.class.getDeclaredField("random");
        randomField.setAccessible(true);
        randomField.set(http, random);

        Field httpClientField = Http.class.getDeclaredField("httpClient");
        httpClientField.setAccessible(true);
        httpClientField.set(http, httpClient);


        Mockito.when(random.nextInt(1000)).thenReturn(RANDOM_INT);
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
                        .build();
                responses.add(resp);
                Mockito.when(call.execute()).thenReturn(resp);

                return call;
            }
        });

        Response actualRes = http.executeHttpRequest();
        assertEquals(Http.MAX_REQUEST_ATTEMPTS, responses.size());
        assertEquals(Http.MAX_REQUEST_ATTEMPTS, calls.size());
        assertEquals(responses.get(responses.size() - 1), actualRes);

        // Verify execution of the new calls
        for (Call call: calls) {
            Mockito.verify(call).execute();
        }

        // Verify the calls to sleep on failures
        ArgumentCaptor<Long> sleepCapture = ArgumentCaptor.forClass(Long.class);
        Mockito.verify(http, Mockito.times(Http.MAX_REQUEST_ATTEMPTS - 1))
                .sleep(sleepCapture.capture());
        List<Long> sleepTimes = sleepCapture.getAllValues();
        assertEquals(1000L + RANDOM_INT, (long) sleepTimes.get(0));
        assertEquals(2000L + RANDOM_INT, (long) sleepTimes.get(1));
        assertEquals(4000L + RANDOM_INT, (long) sleepTimes.get(2));
        assertEquals(8000L + RANDOM_INT, (long) sleepTimes.get(3));
        assertEquals(16000L + RANDOM_INT, (long) sleepTimes.get(4));
        assertEquals(32000L, (long) sleepTimes.get(5));
        assertEquals(32000L, (long) sleepTimes.get(6));
    }
}
