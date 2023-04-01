package com.duosecurity.client.Canonicalization;

public class v1 extends Canonicalizer {
    
    @Override
    public String canonicalize(String method, String host, String url, String queryString) {
        String canon = "";
        canon += method.toUpperCase() + "\n";
        canon += host.toLowerCase() + "\n";
        canon += url + "\n";
        canon += queryString;
        return canon;
    }

}
