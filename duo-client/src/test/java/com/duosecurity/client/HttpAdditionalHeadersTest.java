package com.duosecurity.client;


import org.junit.Test;
import org.junit.Assert;

public class HttpAdditionalHeadersTest {
    private static Http makeHttp() {
        return new Http.HttpBuilder("GET", "example.test", "/foo/bar").build();
    }

    @Test
    public void testAddHeaders(){
        Http h = makeHttp();
        h.addAdditionalHeader("X-Duo-Header-1", "header_value_1");
        h.addAdditionalHeader("X-Duo-Header-2", "header_value_2");
    }

    @Test
    public void testNullHeaderName(){
        Http h = makeHttp();
        try {
            h.addAdditionalHeader(null, "header_value_1");
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
        Http h = makeHttp();
        try {
            h.addAdditionalHeader("", "header_value_1");
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
        Http h = makeHttp();
        try {
            h.addAdditionalHeader("X-Duo-Header-1", null);
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
        Http h = makeHttp();
        try {
            h.addAdditionalHeader("X-Duo-Header-1", "");
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
        Http h = makeHttp();
        try {
            h.addAdditionalHeader("X-not-Duo-Header-1", "header_value_1");
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
        Http h = makeHttp();
        h.addAdditionalHeader("X-Duo-Header-1", "header_value_1");
        try {
            h.addAdditionalHeader("X-DUO-Header-1", "header_value_1");
        }
        catch (IllegalArgumentException e){
            Assert.assertEquals(
                "failure - Header = null",
                new IllegalArgumentException("Duplicate header passed, header=X-DUO-Header-1").toString(), 
                e.toString());
        }
        
    }



}
