package com.duosecurity.client;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.duosecurity.client.Http.HttpBuilder;
import com.google.common.collect.Collections2;
import org.junit.Test;
import org.junit.Assert;

public class HttpCanonV5RequestTest {
    private String date = "Fri, 07 Dec 2012 17:18:00 -0000";

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

    @Test
    public void testPostZeroParams() {
        String actual;
        String expected = date + "\n"
                + "POST\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "\n"
                + "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

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
    public void testPostWithParams() {
        String actual;
        String expected = date + "\n"
                + "POST\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "\n"
                + "2664f5a6463b280a814f9177e53161e8dca3a09e941ac75544f1fd27dde2623cd9c375e15330deebfbd9dc538e743cd7dd2a0199128abc8eccc3bede5f627e56";

        Http h = postHttpBuilder().build();
        h.addParam("data", "abc123");

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
        String expected = date + "\n"
                + "GET\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "\n"
                + "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

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
        String expected = date + "\n"
                + "GET\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "data=abc123\n"
                + "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

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
        String expected = date + "\n"
                + "POST\n"
                + "foo.bar52.com\n"
                + "/Foo/BaR2/qux\n"
                + "\n"
                + "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n"
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
