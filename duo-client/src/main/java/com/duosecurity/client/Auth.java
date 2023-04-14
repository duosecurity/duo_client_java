package com.duosecurity.client;

public class Auth extends Http {
    private Auth(String inMethod, String inHost, String inUri, int timeout) {
        super(inMethod, inHost, inUri, timeout);
    }

    public static class AuthBuilder extends ClientBuilder<Auth> {

        public AuthBuilder(String method, String host, String uri) {
            super(method, host, uri);
        }

        @Override
        protected Auth createClient(String method, String host, String uri, int timeout) {
            return new Auth(method, host, uri, timeout);
        }

    }
}

