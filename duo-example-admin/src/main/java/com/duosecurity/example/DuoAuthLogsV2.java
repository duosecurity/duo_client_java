package com.duosecurity.example;

/*
 * Demo of the Duo Admin API
 *
 * Documentation: http://www.duosecurity.com/docs/adminapi
 */

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.json.JSONArray;
import org.json.JSONObject;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import com.duosecurity.client.Http;

public class DuoAuthLogsV2 {
    private static String proxy_host = null;
    private static int proxy_port = 0;
    public static void main(String[] args) {
        System.out.println("Duo Authlogs V2 Demo");
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
        }
        catch (ParseException parseException) {
            System.err.println(parseException.getMessage());
            formatter.printHelp("DuoAuthLogsV2", options);
            System.exit(1);
            return;
        }
        if (cmd.hasOption("help")) {
            formatter.printHelp("DuoAuthLogsV2", options);
            System.exit(0);
        }

        if (cmd.hasOption("proxy")) {
            Pattern p = Pattern.compile("^([^:]+):(\\d{1,5})$");
            Matcher m = p.matcher(cmd.getOptionValue("proxy"));
            if (m.find()) {
                proxy_host = m.group(1);
                proxy_port = Integer.parseInt(m.group(2));
            }
            else {
                System.out.println("Invalid proxy.");
                System.exit(1);
                return;
            }
        }
        getLogsWithPaging(cmd);
        System.out.println("Done with Admin API demo.");
    }

    
    private static void getLogsWithPaging(CommandLine cmd) {
        JSONObject result;
        JSONObject response;
        JSONObject metadata;
        try {
            // Prepare request.
            Http request = new Http("GET", cmd.getOptionValue("host"), "/admin/v2/logs/authentication");
            String limit = "2";
            long mintime = System.currentTimeMillis() - (180 * 24 * 60 * 60 * 100);
            long maxtime = System.currentTimeMillis();
            request.addParam("mintime", Long.toString(mintime));
            request.addParam("maxtime", Long.toString(maxtime));
            request.addParam("limit", limit);
            request.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"));

            // Use proxy if one was specified.
            if (proxy_host != null) {
                request.setProxy(proxy_host, proxy_port);
            }

            JSONArray offset = null;
            boolean hasMoreLogs = true;
            String next_offset = "";
            while (hasMoreLogs) {
                // Send the request to Duo and parse the response.
                System.out.println("Fetching " + limit + " logs at offset " + offset);

                result = (JSONObject) request.executeJSONRequest();
                response = result.getJSONObject("response");
                metadata = response.getJSONObject("metadata");
                System.out.println(response);

                if (!metadata.isNull("next_offset")) {
                    System.out.println("Getting more logs...");
					offset = metadata.getJSONArray("next_offset");
                    request = new Http("GET", cmd.getOptionValue("host"), "/admin/v2/logs/authentication");
                    next_offset = offset.get(0).toString() + ',' + offset.get(1).toString();
                    request.addParam("next_offset", next_offset);
                    request.addParam("limit", limit);
                    request.addParam("mintime", Long.toString(mintime));
                    request.addParam("maxtime", Long.toString(maxtime));
                    request.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"));

                    System.out.println("More to fetch: next_offset = " + next_offset);
                } else {
                    hasMoreLogs = false;
                    System.out.println("Fetch user request done.");
                }
            }
        }
        catch (Exception e) {
            System.out.println("error making request");
            System.out.println(e.toString());
        }
    }
}
