package com.duosecurity.duoverify.javademo;

/*
 * Demo of the Duo Verify API
 * 
 * Documentation: http://www.duosecurity.com/docs/duoverify
 */

import org.json.JSONObject;

public class DuoVerify {
	
	/*
	 * Add the correct values from a valid Verify API integration
	 */
	private static String IKEY = "";
	private static String SKEY = "";
	private static String HOST = "";
	
	/*
	 * Enter your phone number for testing 
	 * and change the message if you wish
	 */
	private static String PHONE = ""
	private static String MESSAGE = "The PIN is <pin>";

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("Duo Verify Demo");
		
		JSONObject result = null;
		String txid = null;
		
		// Make API call for phone verification
		try{
			Http request = new Http("POST", HOST, "/verify/v1/call.json");
			request.addParam("phone", PHONE);
			request.addParam("message", MESSAGE);
			request.signRequest(IKEY, SKEY);
			
			result = new JSONObject(request.executeRequest());
			request = null; // cleanup the request object
			
			if(result.getString("stat").equals("OK")){
				result.getJSONObject("response").getString("txid");
				
				// Poll the txid for the status of the transaction
				txid = result.getJSONObject("response").getString("txid");
				
				if(txid != null){
					String state = "";
					String info = "";
					
					while(!state.equals("ended")){ // poll until state equals ended						
						request = new Http("GET", HOST, "/verify/v1/status.json");
						request.addParam("txid", txid);
						request.signRequest(IKEY, SKEY);
						
						result = new JSONObject(request.executeRequest());
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
		
		System.out.println("Done with verify demo");

	}
}
