package com.duosecurity.example;

/*
 * Demo policy functionality in the Admin API.
 * 
 * Documentation: https://duo.com/docs/adminapi#policy
 */

import com.duosecurity.client.Admin;
import java.util.ArrayList;
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

public class DuoPolicies {
  private static String proxy_host = null;
  private static int proxy_port = 0;

  /**
   * The main function for the DuoPolicies example that will do the following:
   * 1. print the global policy.
   * 2. create a new policy.
   * 3. page through all polices and print the name.
   * 
   * @param args The command line arguments.
   */
  public static void main(String[] args) {
    System.out.println("Duo Policies Demo");
    Options options = new Options();

    Option opt;
    opt = new Option("host", true, "Admin API hostname (required)");
    opt.setRequired(true);
    options.addOption(opt);

    opt = new Option("ikey", true, "Admin API integration key (required)");
    opt.setRequired(true);
    options.addOption(opt);

    opt = new Option("skey", true, "Admin API secret key (required)");
    opt.setRequired(true);
    options.addOption(opt);

    opt = new Option("proxy", true, "host:port for HTTPS CONNECT proxy");
    opt.setRequired(false);
    options.addOption(opt);

    CommandLineParser parser = new PosixParser();
    HelpFormatter formatter = new HelpFormatter();
    CommandLine cmd;

    try {
      cmd = parser.parse(options, args);
    } catch (ParseException parseException) {
      System.err.println(parseException.getMessage());
      formatter.printHelp("DuoPolicies", options);
      System.exit(1);
      return;
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

    printGlobalPolicy(cmd);
    String newPolicyKey = createNewPolicy(cmd);
    copyPolicy(cmd, newPolicyKey);
    printAllPolicies(cmd);
  }

  /**
   * Print the global policy to stdout.
   * 
   * @param cmd the command line arguments
   */
  private static void printGlobalPolicy(CommandLine cmd) {
    System.out.println("Getting Global Policy");
    try {
      Admin adminRequest = new Admin.AdminBuilder(
          "GET",
          cmd.getOptionValue("host"),
          "/admin/v2/policies/global").build();
      adminRequest.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"));

      // optional proxy
      if (proxy_host != null) {
        adminRequest.setProxy(proxy_host, proxy_port);
      }

      JSONObject result = (JSONObject) adminRequest.executeJSONRequest();
      System.out.println(result.toString(4));
    } catch (Exception e) {
      System.out.println("Error making request");
      System.out.println(e.toString());
    }
  }

  /**
   * Create a new policy and print it to stdout.
   * 
   * @param cmd the command line arguments
   * @return the new policy's policy_key
   */
  private static String createNewPolicy(CommandLine cmd) {
    System.out.println("Creating New Policy");
    try {
      Admin adminRequest = new Admin.AdminBuilder(
          "POST",
          cmd.getOptionValue("host"),
          "/admin/v2/policies").build();
      adminRequest.addParam("policy_name", "New Sample Policy");
      adminRequest.addParam("sections",
          new JSONObject()
              .put("authentication_methods",
                  new JSONObject()
                      .put("allowed_auth_list",
                          new JSONArray()
                              .put("hardware-token")
                              .put("webauthn-platform")
                              .put("webauthn-roaming"))
                      .put("blocked_auth_list",
                          new JSONArray()
                              .put("duo-passcode")
                              .put("phonecall")
                              .put("duo-push")
                              .put("sms"))));
      adminRequest.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"));

      // optional proxy
      if (proxy_host != null) {
        adminRequest.setProxy(proxy_host, proxy_port);
      }

      JSONObject result = (JSONObject) adminRequest.executeJSONRequest();
      System.out.println(result.toString(4));
      return result.getJSONObject("response").getString("policy_key");
    } catch (Exception e) {
      System.out.println("Error making request");
      System.out.println(e.toString());
      return null;
    }
  }

  /**
   * Copy an existing policy twice and print to stdout.
   * 
   * @param cmd           the command line arguments
   * @param policyToCopy  the policy_key to copy
   */
  private static void copyPolicy(CommandLine cmd, String policyToCopy) {
    System.out.println("Copying policy");
    try {
      Admin adminRequest = new Admin.AdminBuilder(
          "POST",
          cmd.getOptionValue("host"),
          "/admin/v2/policies/copy").build();
      adminRequest.addParam("policy_key", policyToCopy);
      adminRequest.addParam("new_policy_names_list", new ArrayList<Object>() {
        {
          add("New Copied Policy 1");
          add("New Copied Policy 2");
        }
      });
      adminRequest.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"));

      // optional proxy
      if (proxy_host != null) {
        adminRequest.setProxy(proxy_host, proxy_port);
      }
      JSONObject result = (JSONObject) adminRequest.executeJSONRequest();
      System.out.println(result.toString(4));
    } catch (Exception e) {
      System.out.println("Error making request");
      System.out.println(e.toString());
    }
  }

  /**
   * Page through all policies and print the names to stdout.
   * 
   * @param cmd the command line arguments
   */
  private static void printAllPolicies(CommandLine cmd) {
    System.out.println("Printing All Policies");
    try {
      int limit = 10;
      int currentOffset = 0;
      while (true) {
        System.out.println("Fetching " + limit + " policies at offset " + currentOffset);

        Admin adminRequest = new Admin.AdminBuilder(
            "GET",
            cmd.getOptionValue("host"),
            "/admin/v2/policies").build();
        adminRequest.addParam("limit", limit);
        adminRequest.addParam("offset", currentOffset);
        adminRequest.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"));

        // optional proxy
        if (proxy_host != null) {
          adminRequest.setProxy(proxy_host, proxy_port);
        }

        JSONObject result = (JSONObject) adminRequest.executeJSONRequest();
        JSONArray policies = result.getJSONArray("response");
        JSONObject metadata = result.getJSONObject("metadata");

        // We are only printing the policy name, but the full details of the policy
        // is available in the policies JSONObject variable.
        for (int x = 0; x < policies.length(); x++) {
          System.out.println(
              String.format(
                  "Policy w/ name: \"%s\"",
                  policies.getJSONObject(x).getString("policy_name")));
        }

        // If next_offset doesn't exist we have reached the end of the dataset.
        if (!metadata.isNull("next_offset")) {
          currentOffset = metadata.getInt("next_offset");
        } else {
          break;
        }
      }
    } catch (Exception e) {
      System.out.println("Error making request");
      System.out.println(e.toString());
    }
  }
}
