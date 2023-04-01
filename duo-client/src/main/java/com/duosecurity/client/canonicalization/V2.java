package com.duosecurity.client.canonicalization;

public class V2 extends Canonicalizer {
    private String date;

    public V2(String inDate) {
        date = inDate;
    }

    @Override
    public String canonicalize(String method, String host, String url, String queryString) {
        String canon = "";
        canon += date + "\n";
        canon += method.toUpperCase() + "\n";
        canon += host.toLowerCase() + "\n";
        canon += url + "\n";
        canon += queryString;
        return canon;
    }
}
