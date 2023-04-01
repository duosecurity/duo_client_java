package com.duosecurity.client.canonicalization;

public abstract class Canonicalizer {
  public abstract String canonicalize(String method, String host, String url, String queryString);
}