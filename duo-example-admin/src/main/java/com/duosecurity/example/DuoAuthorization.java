package com.duosecurity.example;

/*
 * Demo of the Duo Authorization API
 *
 * Documentation: Authorization API for MCP capabilities
 */

import com.duosecurity.client.Admin;
import org.apache.commons.cli.*;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* @Author Abhay Pandit */
public class DuoAuthorization {
    private static String proxy_host = null;
    private static int proxy_port = 0;

    /**
     * The main function for the DuoAuthorization example that will call the
     * /mcp_capabilities/evaluate endpoint.
     *
     * @param args The command line arguments
     */
    public static void main(String[] args) {
        System.out.println("Duo Authorization API Demo");

        Options options = new Options();
        Option opt;
        opt = new Option("host", true, "API hostname (required)");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("ikey", true, "Authorization API integration key (required)");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("skey", true, "Secret key (required)");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("access_token", true, "Access token for authorization (required)");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("mcp_server_id", true, "MCP server ID (required)");
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
            formatter.printHelp("DuoAuthorization", options);
            System.exit(1);
            return;
        }

        if (cmd.hasOption("help")) {
            formatter.printHelp("DuoAuthorization", options);
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

        pingApi(cmd);
        checkCredentials(cmd);
        evaluateMcpCapabilities(cmd);

        System.out.println("Done with Authorization API demo.");
    }

    /**
     * Evaluate MCP capabilities for a given access_token and MCP server ID.
     *
     * @param cmd The command line arguments containing the necessary parameters
     */
    private static void evaluateMcpCapabilities(CommandLine cmd) {
        System.out.println("Evaluating MCP Capabilities...");
        JSONObject result = null;
        try {
            // Prepare request for /authorize/v1/mcp_capabilities/evaluate
            Admin request = new Admin.AdminBuilder("POST",
                    cmd.getOptionValue("host"),
                    "/authorize/v1/mcp_capabilities/evaluate"
            ).build();

            // Add request parameters as JSON body
            request.addParam("access_token", cmd.getOptionValue("access_token"));
            request.addParam("mcp_server_id", cmd.getOptionValue("mcp_server_id"));

            // Sign the request
            request.signRequest(cmd.getOptionValue("ikey"),
                    cmd.getOptionValue("skey"));

            // Use proxy if one was specified
            if (proxy_host != null) {
                request.setProxy(proxy_host, proxy_port);
            }

            // Send the request to Duo and parse the response
            result = (JSONObject) request.executeJSONRequest();

            // Extract and display the response
            System.out.println("Request Status: " + result.getString("stat"));

            if (result.has("response")) {
                JSONObject response = result.getJSONObject("response");

                if (response.has("allowed_capabilities")) {
                    JSONArray allowedCapabilities = response.getJSONArray("allowed_capabilities");
                    System.out.println("Allowed Capabilities:");

                    if (allowedCapabilities.length() == 0) {
                        System.out.println("  No capabilities allowed");
                    } else {
                        for (int i = 0; i < allowedCapabilities.length(); i++) {
                            System.out.println("  - " + allowedCapabilities.getString(i));
                        }
                    }
                }
            }

            // Print full response for debugging
            System.out.println("\nFull Response:");
            System.out.println(result.toString(2));

        } catch (Exception e) {
            System.out.println("Error making request");
            System.out.println(e.toString());
            e.printStackTrace();
        }
    }

    /**
     * Optional: Check endpoint to verify credentials.
     *
     * @param cmd The command line arguments
     */
    private static void checkCredentials(CommandLine cmd) {
        System.out.println("Checking credentials...");
        try {
            Admin request = new Admin.AdminBuilder("GET",
                    cmd.getOptionValue("host"),
                    "/authorize/v1/check").build();

            request.signRequest(cmd.getOptionValue("ikey"),
                    cmd.getOptionValue("skey"));

            if (proxy_host != null) {
                request.setProxy(proxy_host, proxy_port);
            }

            JSONObject result = (JSONObject) request.executeJSONRequest();
            System.out.println("Credentials check result: " + result.getString("stat"));

            if (result.has("response")) {
                JSONObject response = result.getJSONObject("response");
                if (response.has("time")) {
                    System.out.println("Server time: " + response.get("time"));
                }
            }
        } catch (Exception e) {
            System.out.println("Error checking credentials");
            System.out.println(e.toString());
        }
    }

    /**
     * Optional: Ping endpoint to verify API is up.
     *
     * @param cmd The command line arguments
     */
    private static void pingApi(CommandLine cmd) {
        System.out.println("Pinging API...");
        try {
            Admin request = new Admin.AdminBuilder("GET",
                    cmd.getOptionValue("host"),
                    "/authorize/v1/ping").build();

            if (proxy_host != null) {
                request.setProxy(proxy_host, proxy_port);
            }

            // Note: ping endpoint doesn't require authentication
            JSONObject result = (JSONObject) request.executeJSONRequest();
            System.out.println("Ping result: " + result.getString("stat"));

            if (result.has("response")) {
                JSONObject response = result.getJSONObject("response");
                if (response.has("time")) {
                    System.out.println("Server time: " + response.get("time"));
                }
            }
        } catch (Exception e) {
            System.out.println("Error pinging API");
            System.out.println(e.toString());
        }
    }
}
