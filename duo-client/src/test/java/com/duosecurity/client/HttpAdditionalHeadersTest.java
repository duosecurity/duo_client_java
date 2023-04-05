package com.duosecurity.client;


import org.junit.Test;

import com.duosecurity.client.Http.HttpBuilder;

import org.junit.Assert;

public class HttpAdditionalHeadersTest {
    private static HttpBuilder makeHttpBuilder() {
        return new Http.HttpBuilder("GET", "example.test", "/foo/bar");
    }

    @Test
    public void testAddHeaders(){
        HttpBuilder h = makeHttpBuilder();
        h.addAdditionalDuoHeader("X-Duo-Header-1", "header_value_1");
        h.addAdditionalDuoHeader("X-Duo-Header-2", "header_value_2");
    }

    @Test
    public void testNullHeaderName(){
        HttpBuilder h = makeHttpBuilder();
        try {
            h.addAdditionalDuoHeader(null, "header_value_1");
        }
        catch (IllegalArgumentException e){
            Assert.assertEquals(
                "failure - Header = null",
                new IllegalArgumentException("Not allowed 'Null' or empty header name").toString(), 
                e.toString());
        }
        
    }
    @Test
    public void testEmptyHeaderName(){
        HttpBuilder h = makeHttpBuilder();
        try {
            h.addAdditionalDuoHeader("", "header_value_1");
        }
        catch (IllegalArgumentException e){
            Assert.assertEquals(
                "failure - Header = null",
                new IllegalArgumentException("Not allowed 'Null' or empty header name").toString(), 
                e.toString());
        }
        
    }

    @Test
    public void testNullHeaderValue(){
        HttpBuilder h = makeHttpBuilder();
        try {
            h.addAdditionalDuoHeader("X-Duo-Header-1", null);
        }
        catch (IllegalArgumentException e){
            Assert.assertEquals(
                "failure - Header = null",
                new IllegalArgumentException("Not allowed 'Null' or empty header value").toString(), 
                e.toString());
        }
        
    }

    @Test
    public void testEmptyHeaderValue(){
        HttpBuilder h = makeHttpBuilder();
        try {
            h.addAdditionalDuoHeader("X-Duo-Header-1", "");
        }
        catch (IllegalArgumentException e){
            Assert.assertEquals(
                "failure - Header = null",
                new IllegalArgumentException("Not allowed 'Null' or empty header value").toString(), 
                e.toString());
        }
        
    }

    @Test
    public void testNonDuoHeader(){
        HttpBuilder h = makeHttpBuilder();
        try {
            h.addAdditionalDuoHeader("X-not-Duo-Header-1", "header_value_1");
        }
        catch (IllegalArgumentException e){
            Assert.assertEquals(
                "failure - Header = null",
                new IllegalArgumentException("Additional headers must start with \'X-Duo-\'").toString(), 
                e.toString());
        }
        
    }

    @Test
    public void testDuplicatedHeader(){
        HttpBuilder h = makeHttpBuilder();
        h.addAdditionalDuoHeader("X-Duo-Header-1", "header_value_1");
        try {
            h.addAdditionalDuoHeader("X-DUO-Header-1", "header_value_1");
        }
        catch (IllegalArgumentException e){
            Assert.assertEquals(
                "failure - Header = null",
                new IllegalArgumentException("Duplicate header passed, header=X-DUO-Header-1").toString(), 
                e.toString());
        }
        
    }
}
