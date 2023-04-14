package com.duosecurity.client;


import org.junit.Test;

import com.duosecurity.client.Admin.AdminBuilder;

import org.junit.Assert;

public class HttpAdditionalHeadersTest {
    private static AdminBuilder makeAdminBuilder() {
        return new Admin.AdminBuilder("GET", "example.test", "/foo/bar");
    }

    @Test
    public void testAddHeaders(){
        AdminBuilder h = makeAdminBuilder();
        h.addAdditionalDuoHeader("X-Duo-Header-1", "header_value_1");
        h.addAdditionalDuoHeader("X-Duo-Header-2", "header_value_2");
    }

    @Test
    public void testNullHeaderName(){
        AdminBuilder h = makeAdminBuilder();
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
        AdminBuilder h = makeAdminBuilder();
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
        AdminBuilder h = makeAdminBuilder();
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
        AdminBuilder h = makeAdminBuilder();
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
        AdminBuilder h = makeAdminBuilder();
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
        AdminBuilder h = makeAdminBuilder();
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
