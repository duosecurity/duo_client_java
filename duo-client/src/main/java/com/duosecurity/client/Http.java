package com.duosecurity.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.message.HeaderGroup;

import org.json.JSONObject;

public class Http {
    private String method;
    private String host;
    private String uri;
    private HeaderGroup headers;
    private ArrayList<NameValuePair> params;

    public Http(String in_method, String in_host, String in_uri) {
        method = in_method;
        host = in_host;
        uri = in_uri;

        headers = new HeaderGroup();
        addHeader("Host", host);

        params = new ArrayList<NameValuePair>();
    }

    public JSONObject executeRequest() throws Exception {
        JSONObject result = new JSONObject(executeRequestRaw());
        if (! result.getString("stat").equals("OK")) {
            throw new Exception("Duo error code ("
                                + result.getInt("code")
                                + "): "
                                + result.getString("message"));
        }
        return result;
    }

    public String executeRequestRaw() throws Exception {
        HttpResponse response;
        HttpClient httpclient = new DefaultHttpClient();

        String url = "https://" + host + uri;
        String queryString = createQueryString();

        if (method.equals("GET")) {
            if (queryString.length() > 0) {
                url += "?" + queryString;
            }
            HttpGet request = new HttpGet(url);
            request.setHeaders(headers.getAllHeaders());
            response = httpclient.execute(request);
        } else {
            HttpPost request = new HttpPost(url);
            request.setHeaders(headers.getAllHeaders());
            request.setEntity(new UrlEncodedFormEntity(params));
            response = httpclient.execute(request);
        }

        InputStream stream = response.getEntity().getContent();
        String buf = streamToString(stream);
        return buf;
    }

    public void signRequest(String ikey, String skey) {
        String sig;
        String canon = canonRequest();

        sig = signHMAC(skey, canon);

        String auth = ikey + ":" + sig;
        String header = "Basic " + Base64.encodeBytes(auth.getBytes());
        addHeader("Authorization", header);
    }

    private String signHMAC(String skey, String msg) {
        try {
            byte[] sig_bytes = Util.hmacSha1(skey.getBytes(), msg.getBytes());
            String sig = Util.bytes_to_hex(sig_bytes);
            return sig;
        } catch (Exception e) {
            return "";
        }
    }

    public void addHeader(String name, String value) {
        headers.addHeader(new BasicHeader(name, value));
    }

    public void addParam(String name, String value) {
        params.add(new BasicNameValuePair(name, value));
    }

    private String canonRequest() {
        String canon = "";
        canon += method.toUpperCase() + "\n";
        canon += host.toLowerCase() + "\n";
        canon += uri + "\n";
        canon += createQueryString();

        return canon;
    }

    private String streamToString(InputStream stream) {
        BufferedReader reader = new BufferedReader(
                                                   new InputStreamReader(stream));
        StringBuilder sb = new StringBuilder();
        String line = null;

        try {
            while ((line = reader.readLine()) != null) {
                sb.append(line + "\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                stream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return sb.toString();
    }

    private String createQueryString() {
        ArrayList<String> args = new ArrayList<String>();
        ArrayList<String> keys = new ArrayList<String>();

        for (NameValuePair pair : params) {
            keys.add(pair.getName());
        }

        Collections.sort(keys);

        for (String key : keys) {
            for (NameValuePair pair : params) {
                if (key.equals(pair.getName())) {
                    try {
                        String name = URLEncoder
                            .encode(pair.getName(), "UTF-8")
                            .replace("+", "%20").replace("*", "%2A")
                            .replace("%7E", "~");
                        String value = URLEncoder
                            .encode(pair.getValue(), "UTF-8")
                            .replace("+", "%20").replace("*", "%2A")
                            .replace("%7E", "~");
                        args.add(name + "=" + value);
                        break;
                    } catch (Exception e) {
                        System.out.println(e.toString());
                        System.exit(0);
                    }

                }
            }
        }

        return Util.join(args.toArray(), "&");

    }
}
