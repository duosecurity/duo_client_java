package com.duosecurity.example;

/*
 * Demo of the Duo Admin API
 *
 * Documentation: http://www.duosecurity.com/docs/adminapi
 */

import java.util.Iterator;

import org.json.JSONObject;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import com.duosecurity.client.Http;

public class DuoAdmin {
    public static void main(String[] args) {
        System.out.println("Duo Admin Demo");

        Options options = new Options();
        Option opt;
        opt = new Option("host", true, "API hostname");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("ikey", true, "Admin API integration key");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("skey", true, "Secret key");
        opt.setRequired(true);
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
            formatter.printHelp("DuoAdmin", options);
            System.exit(1);
            return;
        }

        if (cmd.hasOption("help")) {
            formatter.printHelp("DuoAdmin", options);
            System.exit(0);
        }

        JSONObject result = null;
        try{
            Http request = new Http("GET",
                                    cmd.getOptionValue("host"),
                                    "/admin/v1/info/authentication_attempts");
            request.signRequest(cmd.getOptionValue("ikey"),
                                cmd.getOptionValue("skey"));
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
        }
        catch (Exception e) {
            System.out.println("error making request");
            System.out.println(e.toString());
        }

        System.out.println("Done with Admin API demo.");
    }
}
