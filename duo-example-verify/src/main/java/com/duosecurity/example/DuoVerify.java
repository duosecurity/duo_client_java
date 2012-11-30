package com.duosecurity.example;

/*
 * Demo of the Duo Verify API
 *
 * Documentation: http://www.duosecurity.com/docs/duoverify
 */

import org.json.JSONObject;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import com.duosecurity.client.Http;

public class DuoVerify {
    private static String MESSAGE = "The PIN is <pin>";

    public static void main(String[] args) {
        System.out.println("Duo Verify Demo");

        Options options = new Options();
        Option opt;
        opt = new Option("host", true, "API hostname");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("ikey", true, "Verify integration key");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("skey", true, "Secret key");
        opt.setRequired(true);
        options.addOption(opt);
        opt = new Option("phone", true, "E.164-formatted phone number");
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
            formatter.printHelp("DuoVerify", options);
            System.exit(1);
            return;
        }

        if (cmd.hasOption("help")) {
            formatter.printHelp("DuoVerify", options);
            System.exit(0);
        }

        JSONObject result = null;
        String txid = null;

        // Make API call for phone verification
        try{
            Http request = new Http("POST",
                                    cmd.getOptionValue("host"),
                                    "/verify/v1/call.json");
            request.addParam("phone",
                             cmd.getOptionValue("phone"));
            request.addParam("message", MESSAGE);
            request.signRequest(cmd.getOptionValue("ikey"),
                                cmd.getOptionValue("skey"));

            result = request.executeRequest();
            request = null; // cleanup the request object

            if(result.getString("stat").equals("OK")){
                result.getJSONObject("response").getString("txid");

                // Poll the txid for the status of the transaction
                txid = result.getJSONObject("response").getString("txid");

                if(txid != null){
                    String state = "";
                    String info = "";

                    while(!state.equals("ended")){ // poll until state equals ended
                        request = new Http("GET",
                                           cmd.getOptionValue("host"),
                                           "/verify/v1/status.json");
                        request.addParam("txid", txid);
                        request.signRequest(cmd.getOptionValue("ikey"),
                                            cmd.getOptionValue("skey"));

                        result = request.executeRequest();
                        state = result.getJSONObject("response").getString("state");
                        info = result.getJSONObject("response").getString("info");

                        System.out.println("Call status: " +  info);
                    }
                }
            }
        }
        catch(Exception e) {
            System.out.println("error making request");
            System.out.println(e.toString());
        }

        System.out.println("Done with verify demo.");
    }
}
