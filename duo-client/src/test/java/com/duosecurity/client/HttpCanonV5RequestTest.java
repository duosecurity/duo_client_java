package com.duosecurity.client;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

import com.duosecurity.client.Http.HttpBuilder;
import org.junit.Test;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Assert;

public class HttpCanonV5RequestTest {
    private String date = "Fri, 07 Dec 2012 17:18:00 -0000";
    private final String hashingAlgorithm = "SHA-512";
    String hashedBody;
    String hasedEmptyAdditionalHeader = getHashedMessage("");

    private static HttpBuilder postHttpBuilder() {
        // deliberately use the "wrong" case for method and host,
        // checking that those get canonicalized but URI's case is
        // preserved.
        return new Http.HttpBuilder("PoSt", "foO.BAr52.cOm", "/Foo/BaR2/qux");
    }

    private static HttpBuilder getHttpBuilder() {
        // deliberately use the "wrong" case for method and host,
        // checking that those get canonicalized but URI's case is
        // preserved.
        return new Http.HttpBuilder("gEt", "foO.BAr52.cOm", "/Foo/BaR2/qux");
    }

    private String getHashedMessage(String message) {
        return Util.bytes_to_hex(Util.hash(hashingAlgorithm, message));
    }

    @Test
    public void testPostZeroParams() {
        String actual;
        hashedBody = getHashedMessage("{}");

        String expected = date + "\n"
                + "POST\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "\n"
                + hashedBody + "\n"
                + hasedEmptyAdditionalHeader;

        Http h = postHttpBuilder().build();
        try {
            actual = h.canonRequest(date, 5);
        } catch (UnsupportedEncodingException e) {
            Assert.fail(e.toString());
            return;
        }
        Assert.assertEquals("failure - Canonicalization v5 with no params for POST",
                expected,
                actual);
    }

    @Test
    public void testPostWithParams() throws JSONException {
        String actual;
        String jsonBody = "{\"data\":\"abc123\",\"alpha\":[\"a\",\"b\",\"c\",\"d\"],\"info\":{\"test\":1,\"anther\":2}}";
        hashedBody = getHashedMessage(jsonBody);
        String expected = date + "\n"
                + "POST\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "\n"
                + hashedBody + "\n"
                + hasedEmptyAdditionalHeader;

        Http h = postHttpBuilder().build();
        h.addParam("data", "abc123");
        h.addParam("alpha", new ArrayList<Object>() {
            {
                add("a");
                add("b");
                add("c");
                add("d");
            }
        });
        h.addParam("info", new JSONObject() {
            {
                put("test", 1);
                put("anther", 2);
            }
        });

        try {
            actual = h.canonRequest(date, 5);
        } catch (UnsupportedEncodingException e) {
            Assert.fail(e.toString());
            return;
        }
        Assert.assertEquals("failure - Canonicalization v5 with params for POST",
                expected,
                actual);
    }

    @Test
    public void testGetZeroParams() {
        String actual;
        hashedBody = getHashedMessage("");
        String expected = date + "\n"
                + "GET\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "\n"
                + hashedBody + "\n"
                + hasedEmptyAdditionalHeader;

        Http h = getHttpBuilder().build();
        try {
            actual = h.canonRequest(date, 5);
        } catch (UnsupportedEncodingException e) {
            Assert.fail(e.toString());
            return;
        }
        Assert.assertEquals("failure - Canonicalization v5 with no params for GET",
                expected,
                actual);
    }

    @Test
    public void testGetWithParams() {
        String actual;
        hashedBody = getHashedMessage("");
        String expected = date + "\n"
                + "GET\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "data=abc123\n"
                + hashedBody + "\n"
                + hasedEmptyAdditionalHeader;

        Http h = getHttpBuilder().build();
        h.addParam("data", "abc123");
        try {
            actual = h.canonRequest(date, 5);
        } catch (UnsupportedEncodingException e) {
            Assert.fail(e.toString());
            return;
        }
        Assert.assertEquals("failure - Canonicalization v5 with params for GET",
                expected,
                actual);
    }

    @Test
    public void testDuoHeaders() {
        String actual;
        hashedBody = getHashedMessage("{}");
        String expected = date + "\n"
                + "POST\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "\n"
                + hashedBody + "\n"
                + "60be11a30e0756f2ee2afdce1db849b987dcf86c1133394bd7bbbc9877920330c4d78aceacbb377ab8cbd9a8efe6a410fed4047376635ac71226ab46ca10d2b1";

        HttpBuilder httpBuilder = postHttpBuilder();
        httpBuilder.addAdditionalDuoHeader("x-duo-A", "header_value_1");
        httpBuilder.addAdditionalDuoHeader("X-duo-B", "header_value_2");
        Http h = httpBuilder.build();
        try {
            actual = h.canonRequest(date, 5);
        } catch (UnsupportedEncodingException e) {
            Assert.fail(e.toString());
            return;
        }
        Assert.assertEquals("failure - Canonicalization v5 with additional headers",
                expected,
                actual);
    }

}
