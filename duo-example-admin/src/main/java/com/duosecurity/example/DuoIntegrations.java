package com.duosecurity.example;

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
import org.json.JSONObject;

import com.duosecurity.client.Admin;

public class DuoIntegrations {
    private static String proxy_host = null;
    private static int proxy_port = 0;

    public static void main(String[] args) {
        System.out.println("Duo Integration Demo");

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
        create_integration(cmd);
        System.out.println("Done with Integration API demo.");
    }

    private static void create_integration(CommandLine cmd) {
        JSONObject result;
        JSONObject response;

        try {
            // Prepare request.
            Admin request = new Admin.AdminBuilder("POST", cmd.getOptionValue("host"), "/admin/v2/integrations").build();
            request.addParam("name", "api-created integration");
            request.addParam("type", "sso-generic");
            request.addParam("sso", new JSONObject() {
                {
                    put("saml_config", new JSONObject() {
                        {
                            put("entity_id", "entity_id");
                            put("acs_urls", new ArrayList<Object>() {
                                {
                                    add(
                                            new JSONObject() {
                                                {
                                                    put("url", "https://example.com/acs");
                                                    put("binding", JSONObject.NULL);
                                                    put("isDefault", JSONObject.NULL);
                                                    put("index", JSONObject.NULL);
                                                }
                                            });
                                }
                            });
                            put("nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                            put("nameid_attribute", "mail");
                            put("sign_assertion", false);
                            put("sign_response", true);
                            put("signing_algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                            put("mapped_attrs", new JSONObject());
                            put("relaystate", "https://example.com/relaystate");
                            put("slo_url", "https://example.com/slo");
                            put("spinitiated_url", "https://example.com/spurl");
                            put("static_attrs", new JSONObject());
                            put("role_attrs", new JSONObject() {
                                {
                                    put("bob", new JSONObject() {
                                        {
                                            put("ted", new ArrayList<String>() {
                                                {
                                                    add("DGS08MMO53GNRLSFW0D0");
                                                    add("DGETXINZ6CSJO4LRSVKV");
                                                }
                                            });
                                            put("frank", new ArrayList<String>() {
                                                {
                                                    add("DGETXINZ6CSJO4LRSVKV");
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                            put("attribute_transformations", new JSONObject() {
                                {
                                    put("attribute_1", "use \"<Username>\"\nprepend text=\"dev-\"");
                                    put("attribute_2",
                                            "use \"<Email Address>\"\nappend additional_attr=\"<First Name>\"");
                                }
                            });

                        }
                    });
                }
            });
            request.signRequest(cmd.getOptionValue("ikey"), cmd.getOptionValue("skey"), 5);

            // Use proxy if one was specified.
            if (proxy_host != null) {
                request.setProxy(proxy_host, proxy_port);
            }

            System.out.println("Creating new SSO integration");
            result = (JSONObject) request.executeJSONRequest();
            response = result.getJSONObject("response");
            System.out.println("Created integration:");
            System.out.println(response);

        } catch (Exception e) {
            System.out.println("error making request");
            System.out.println(e.toString());
        }

    }

}
