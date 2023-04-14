package com.duosecurity.example;

/*
 * Demo of the Duo Admin API
 *
 * Documentation: http://www.duosecurity.com/docs/adminapi
 */

import com.duosecurity.client.Admin;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.json.JSONArray;
import org.json.JSONObject;

public class DuoAdmin {
  private static String proxy_host = null;
  private static int proxy_port = 0;

  /**
   * The main function for the DuoAdmin example that will get users and authentication attempts.
   *
   * @param args    The command line arguments
   */
  public static void main(String[] args) {
    System.out.println("Duo Admin Demo");

    Options options = new Options();
    Option opt;
    opt = new Option("host", true, "API hostname (required)");
    opt.setRequired(true);
    options.addOption(opt);
    opt = new Option("ikey", true, "Admin API integration key (required)");
    opt.setRequired(true);
    options.addOption(opt);
    opt = new Option("skey", true, "Secret key (required)");
    opt.setRequired(true);
    options.addOption(opt);
    opt = new Option("proxy", true, "host:port for HTTPS CONNECT proxy");
    opt.setRequired(false);
    options.addOption(opt);
    options.addOption("help", false, "Print this message");

    CommandLineParser parser = new PosixParser();
    HelpFormatter formatter = new HelpFormatter();
    CommandLine cmd;
    try {
      cmd = parser.parse(options, args);
    } catch (ParseException parseException) {
      System.err.println(parseException.getMessage());
      formatter.printHelp("DuoAdmin", options);
      System.exit(1);
      return;
    }

    if (cmd.hasOption("help")) {
      formatter.printHelp("DuoAdmin", options);
      System.exit(0);
    }

    if (cmd.hasOption("proxy")) {
      Pattern p = Pattern.compile("^([^:]+):(\\d{1,5})$");
      Matcher m = p.matcher(cmd.getOptionValue("proxy"));
      if (m.find()) {
        proxy_host = m.group(1);
        proxy_port = Integer.parseInt(m.group(2));
      } else {
        System.out.println("Invalid proxy.");
        System.exit(1);
        return;
      }
    }

    getAuthenticationAttempts(cmd);
    getUsersWithPaging(cmd);

    System.out.println("Done with Admin API demo.");
  }

  private static void getAuthenticationAttempts(CommandLine cmd) {
    JSONObject result = null;
    try {
      // Prepare request.
      Admin request = new Admin.AdminBuilder("GET",
                                cmd.getOptionValue("host"),
                                "/admin/v1/info/authentication_attempts").build();
      request.signRequest(cmd.getOptionValue("ikey"),
                          cmd.getOptionValue("skey"));

      // Use proxy if one was specified.
      if (proxy_host != null) {
        request.setProxy(proxy_host, proxy_port);
      }

      // Send the request to Duo and parse the response.
      result = (JSONObject)request.executeRequest();
      System.out.println("mintime = " + result.getInt("mintime"));
      System.out.println("maxtime = " + result.getInt("maxtime"));

      JSONObject attempts
          = result.getJSONObject("authentication_attempts");
      Iterator<?> keys = attempts.keys();
      while (keys.hasNext()) {
        String key = (String)keys.next();
        System.out.println(key + " count = " + attempts.getInt(key));
      }
    } catch (Exception e) {
      System.out.println("error making request");
      System.out.println(e.toString());
    }
  }

  private static void getUsersWithPaging(CommandLine cmd) {
    JSONObject result;
    JSONArray response;
    JSONObject metadata;
    try {
      // Prepare request.
      Admin request = new Admin.AdminBuilder("GET", cmd.getOptionValue("host"), "/admin/v1/users").build();
      String limit = "10";
      request.addParam("offset", "0");
      request.addParam("limit", limit);
      request.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"));

      // Use proxy if one was specified.
      if (proxy_host != null) {
        request.setProxy(proxy_host, proxy_port);
      }

      int offset = 0;
      boolean hasMoreUsers = true;
      while (hasMoreUsers) {
        // Send the request to Duo and parse the response.
        System.out.println("Fetching " + limit + " users at offset " + offset);

        result = (JSONObject) request.executeJSONRequest();
        response = result.getJSONArray("response");
        metadata = result.getJSONObject("metadata");

        if (!metadata.isNull("next_offset")) {
          offset = metadata.getInt("next_offset");

          request = new Admin.AdminBuilder("GET", cmd.getOptionValue("host"), "/admin/v1/users").build();
          request.addParam("offset", Integer.toString(offset));
          request.addParam("limit", limit);
          request.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"));

          System.out.println("More to fetch: next_offset = " + offset);
        } else {
          hasMoreUsers = false;
          System.out.println("Fetch user request done.");
        }

        // iterate users and print them
        for (int i = 0; i < response.length(); i++) {
          JSONObject user = response.getJSONObject(i);
          System.out.println("Fetched user: " + user.get("username"));
        }
      }
    } catch (Exception e) {
      System.out.println("error making request");
      System.out.println(e.toString());
    }
  }
}
