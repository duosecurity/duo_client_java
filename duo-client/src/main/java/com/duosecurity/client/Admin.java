package com.duosecurity.client;

public class Admin extends Http {
  private Admin(String inMethod, String inHost, String inUri, int timeout) {
    super(inMethod, inHost, inUri, timeout);
  }

  public static class AdminBuilder extends ClientBuilder<Admin> {

    public AdminBuilder(String method, String host, String uri) {
      super(method, host, uri);
    }

    @Override
    protected Admin createClient(String method, String host, String uri, int timeout) {
      return new Admin(method, host, uri, timeout);
    }

  }
}
