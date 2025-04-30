package com.duosecurity.client;

import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import okhttp3.CertificatePinner;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONObject;

public class Http {
  public static final int BACKOFF_FACTOR = 2;
  public static final int INITIAL_BACKOFF_MS = 1000;
  public static final int MAX_BACKOFF_MS = 32000;
  public static final int DEFAULT_TIMEOUT_SECS = 60;
  private static final int RATE_LIMIT_ERROR_CODE = 429;

  public static final String UserAgentString = "Duo API Java/0.7.0";

  private final String method;
  private final String host;
  private final String uri;
  private final String signingAlgorithm = "HmacSHA512";
  private final String hashingAlgorithm = "SHA-512";
  private Headers.Builder headers;
  private SortedMap<String, Object> params = new TreeMap<String, Object>();
  protected int sigVersion = 5;
  private Random random = new Random();
  private OkHttpClient httpClient;
  private SortedMap<String, String> additionalDuoHeaders = new TreeMap<String, String>();

  public static SimpleDateFormat RFC_2822_DATE_FORMAT = 
      new SimpleDateFormat("EEE', 'dd' 'MMM' 'yyyy' 'HH:mm:ss' 'Z", Locale.US);

  public static MediaType FORM_ENCODED = MediaType.parse("application/x-www-form-urlencoded");
  public static MediaType JSON_ENCODED = MediaType.parse("application/json");

  private static final String[] DEFAULT_CA_CERTS = {
      //Source URL: https://www.amazontrust.com/repository/AmazonRootCA1.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Amazon Root CA 1,O=Amazon,C=US
      //Issuer: CN=Amazon Root CA 1,O=Amazon,C=US
      //Expiration Date: 2038-01-17 00:00:00
      //Serial Number: 66C9FCF99BF8C0A39E2F0788A43E696365BCA
      //SHA256 Fingerprint: 8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e
      "sha256/MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n"
      + "ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n"
      + "b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n"
      + "MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n"
      + "b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n"
      + "ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n"
      + "9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n"
      + "IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n"
      + "VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n"
      + "93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n"
      + "jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
      + "AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n"
      + "A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n"
      + "U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n"
      + "N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n"
      + "o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n"
      + "5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n"
      + "rqXRfboQnoZsG4q5WTP468SQvvG5",
      //Source URL: https://www.amazontrust.com/repository/AmazonRootCA2.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Amazon Root CA 2,O=Amazon,C=US
      //Issuer: CN=Amazon Root CA 2,O=Amazon,C=US
      //Expiration Date: 2040-05-26 00:00:00
      //Serial Number: 66C9FD29635869F0A0FE58678F85B26BB8A37
      //SHA256 Fingerprint: 1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4
      "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\n"
      + "4PsJYGw=",
      //Source URL: https://www.amazontrust.com/repository/AmazonRootCA3.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Amazon Root CA 3,O=Amazon,C=US
      //Issuer: CN=Amazon Root CA 3,O=Amazon,C=US
      //Expiration Date: 2040-05-26 00:00:00
      //Serial Number: 66C9FD5749736663F3B0B9AD9E89E7603F24A
      //SHA256 Fingerprint: 18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4
      "sha256/MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5\n"
      + "MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g\n"
      + "Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG\n"
      + "A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg\n"
      + "Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl\n"
      + "ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j\n"
      + "QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr\n"
      + "ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr\n"
      + "BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM\n"
      + "YyRIHN8wfdVoOw==",
      //Source URL: https://www.amazontrust.com/repository/AmazonRootCA4.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Amazon Root CA 4,O=Amazon,C=US
      //Issuer: CN=Amazon Root CA 4,O=Amazon,C=US
      //Expiration Date: 2040-05-26 00:00:00
      //Serial Number: 66C9FD7C1BB104C2943E5717B7B2CC81AC10E
      //SHA256 Fingerprint: e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092
      "sha256/MIIB8jCCAXigAwIBAgITBmyf18G7EEwpQ+Vxe3ssyBrBDjAKBggqhkjOPQQDAzA5\n"
      + "MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g\n"
      + "Um9vdCBDQSA0MB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG\n"
      + "A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg\n"
      + "Q0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN/sGKe0uoe0ZLY7Bi\n"
      + "9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri83Bk\n"
      + "M6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKNCMEAwDwYDVR0TAQH/BAUwAwEB\n"
      + "/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFNPsxzplbszh2naaVvuc84ZtV+WB\n"
      + "MAoGCCqGSM49BAMDA2gAMGUCMDqLIfG9fhGt0O9Yli/W651+kI0rz2ZVwyzjKKlw\n"
      + "CkcO8DdZEv8tmZQoTipPNU0zWgIxAOp1AE47xDqUEpHJWEadIRNyp4iciuRMStuW\n"
      + "1KyLa2tJElMzrdfkviT8tQp21KW8EA==",
      //Source URL: https://www.amazontrust.com/repository/SFSRootCAG2.cer
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=Starfield Services Root Certificate Authority - G2,
      // O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
      //Issuer: CN=Starfield Services Root Certificate Authority - G2,
      // O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
      //Expiration Date: 2037-12-31 23:59:59
      //Serial Number: 0
      //SHA256 Fingerprint: 568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5
      "sha256/MIID7zCCAtegAwIBAgIBADANBgkqhkiG9w0BAQsFADCBmDELMAkGA1UEBhMCVVMx\n"
      + "EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoT\n"
      + "HFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xOzA5BgNVBAMTMlN0YXJmaWVs\n"
      + "ZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5\n"
      + "MDkwMTAwMDAwMFoXDTM3MTIzMTIzNTk1OVowgZgxCzAJBgNVBAYTAlVTMRAwDgYD\n"
      + "VQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFy\n"
      + "ZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTswOQYDVQQDEzJTdGFyZmllbGQgU2Vy\n"
      + "dmljZXMgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZI\n"
      + "hvcNAQEBBQADggEPADCCAQoCggEBANUMOsQq+U7i9b4Zl1+OiFOxHz/Lz58gE20p\n"
      + "OsgPfTz3a3Y4Y9k2YKibXlwAgLIvWX/2h/klQ4bnaRtSmpDhcePYLQ1Ob/bISdm2\n"
      + "8xpWriu2dBTrz/sm4xq6HZYuajtYlIlHVv8loJNwU4PahHQUw2eeBGg6345AWh1K\n"
      + "Ts9DkTvnVtYAcMtS7nt9rjrnvDH5RfbCYM8TWQIrgMw0R9+53pBlbQLPLJGmpufe\n"
      + "hRhJfGZOozptqbXuNC66DQO4M99H67FrjSXZm86B0UVGMpZwh94CDklDhbZsc7tk\n"
      + "6mFBrMnUVN+HL8cisibMn1lUaJ/8viovxFUcdUBgF4UCVTmLfwUCAwEAAaNCMEAw\n"
      + "DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJxfAN+q\n"
      + "AdcwKziIorhtSpzyEZGDMA0GCSqGSIb3DQEBCwUAA4IBAQBLNqaEd2ndOxmfZyMI\n"
      + "bw5hyf2E3F/YNoHN2BtBLZ9g3ccaaNnRbobhiCPPE95Dz+I0swSdHynVv/heyNXB\n"
      + "ve6SbzJ08pGCL72CQnqtKrcgfU28elUSwhXqvfdqlS5sdJ/PHLTyxQGjhdByPq1z\n"
      + "qwubdQxtRbeOlKyWN7Wg0I8VRw7j6IPdj/3vQQF3zCepYoUz8jcI73HPdwbeyBkd\n"
      + "iEDPfUYd/x7H4c7/I9vG+o1VTqkC50cRRj70/b17KSa7qWFiNyi2LSr2EIZkyXCn\n"
      + "0q23KXB56jzaYyWf/Wi3MOxw+3WKt21gZ7IeyLnp2KhvAotnDU0mV3HaIPzBSlCN\n"
      + "sSi6",
      //Source URL: https://cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
      //Issuer: CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
      //Expiration Date: 2031-11-10 00:00:00
      //Serial Number: 2AC5C266A0B409B8F0B79F2AE462577
      //SHA256 Fingerprint: 7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
      "sha256/MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs\n"
      + "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
      + "d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"
      + "ZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL\n"
      + "MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\n"
      + "LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug\n"
      + "RVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm\n"
      + "+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW\n"
      + "PNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEM\n"
      + "xChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB\n"
      + "Ik5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3\n"
      + "hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg\n"
      + "EsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF\n"
      + "MAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA\n"
      + "FLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec\n"
      + "nzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6z\n"
      + "eM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF\n"
      + "hS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2\n"
      + "Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe\n"
      + "vEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep\n"
      + "+OkuE6N36B9K",
      //Source URL: https://cacerts.digicert.com/DigiCertTLSECCP384RootG5.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US
      //Issuer: CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US
      //Expiration Date: 2046-01-14 23:59:59
      //Serial Number: 9E09365ACF7D9C8B93E1C0B042A2EF3
      //SHA256 Fingerprint: 018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05
      "sha256/MIICGTCCAZ+gAwIBAgIQCeCTZaz32ci5PhwLBCou8zAKBggqhkjOPQQDAzBOMQsw\n"
      + "CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJjAkBgNVBAMTHURp\n"
      + "Z2lDZXJ0IFRMUyBFQ0MgUDM4NCBSb290IEc1MB4XDTIxMDExNTAwMDAwMFoXDTQ2\n"
      + "MDExNDIzNTk1OVowTjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ\n"
      + "bmMuMSYwJAYDVQQDEx1EaWdpQ2VydCBUTFMgRUNDIFAzODQgUm9vdCBHNTB2MBAG\n"
      + "ByqGSM49AgEGBSuBBAAiA2IABMFEoc8Rl1Ca3iOCNQfN0MsYndLxf3c1TzvdlHJS\n"
      + "7cI7+Oz6e2tYIOyZrsn8aLN1udsJ7MgT9U7GCh1mMEy7H0cKPGEQQil8pQgO4CLp\n"
      + "0zVozptjn4S1mU1YoI71VOeVyaNCMEAwHQYDVR0OBBYEFMFRRVBZqz7nLFr6ICIS\n"
      + "B4CIfBFqMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49\n"
      + "BAMDA2gAMGUCMQCJao1H5+z8blUD2WdsJk6Dxv3J+ysTvLd6jLRl0mlpYxNjOyZQ\n"
      + "LgGheQaRnUi/wr4CMEfDFXuxoJGZSZOoPHzoRgaLLPIxAJSdYsiJvRmEFOml+wG4\n"
      + "DXZDjC5Ty3zfDBeWUA==",
      //Source URL: https://cacerts.digicert.com/DigiCertTLSRSA4096RootG5.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=DigiCert TLS RSA4096 Root G5,O=DigiCert\, Inc.,C=US
      //Issuer: CN=DigiCert TLS RSA4096 Root G5,O=DigiCert\, Inc.,C=US
      //Expiration Date: 2046-01-14 23:59:59
      //Serial Number: 8F9B478A8FA7EDA6A333789DE7CCF8A
      //SHA256 Fingerprint: 371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75
      "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",
      //Source URL: https://secure.globalsign.com/cacert/rootr46.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE
      //Issuer: CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE
      //Expiration Date: 2046-03-20 00:00:00
      //Serial Number: 11D2BBB9D723189E405F0A9D2DD0DF2567D1
      //SHA256 Fingerprint: 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",
      //Source URL: https://secure.globalsign.com/cacert/roote46.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=GlobalSign Root E46,O=GlobalSign nv-sa,C=BE
      //Issuer: CN=GlobalSign Root E46,O=GlobalSign nv-sa,C=BE
      //Expiration Date: 2046-03-20 00:00:00
      //Serial Number: 11D2BBBA336ED4BCE62468C50D841D98E843
      //SHA256 Fingerprint: cbb9c44d84b8043e1050ea31a69f514955d7bfd2e2c6b49301019ad61d9f5058
      "sha256/MIICCzCCAZGgAwIBAgISEdK7ujNu1LzmJGjFDYQdmOhDMAoGCCqGSM49BAMDMEYx\n"
      + "CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRwwGgYDVQQD\n"
      + "ExNHbG9iYWxTaWduIFJvb3QgRTQ2MB4XDTE5MDMyMDAwMDAwMFoXDTQ2MDMyMDAw\n"
      + "MDAwMFowRjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex\n"
      + "HDAaBgNVBAMTE0dsb2JhbFNpZ24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQA\n"
      + "IgNiAAScDrHPt+ieUnd1NPqlRqetMhkytAepJ8qUuwzSChDH2omwlwxwEwkBjtjq\n"
      + "R+q+soArzfwoDdusvKSGN+1wCAB16pMLey5SnCNoIwZD7JIvU4Tb+0cUB+hflGdd\n"
      + "yXqBPCCjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud\n"
      + "DgQWBBQxCpCPtsad0kRLgLWi5h+xEk8blTAKBggqhkjOPQQDAwNoADBlAjEA31SQ\n"
      + "7Zvvi5QCkxeCmb6zniz2C5GMn0oUsfZkvLtoURMMA/cVi4RguYv/Uo7njLwcAjA8\n"
      + "+RHUjE7AwWHCFUyqqx0LMV87HOIAl0Qx5v5zli/altP+CAezNIm8BZ/3Hobui3A=",
      //Source URL: https://i.pki.goog/r2.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=GTS Root R2,O=Google Trust Services LLC,C=US
      //Issuer: CN=GTS Root R2,O=Google Trust Services LLC,C=US
      //Expiration Date: 2036-06-22 00:00:00
      //Serial Number: 203E5AEC58D04251AAB1125AA
      //SHA256 Fingerprint: 8d25cd97229dbf70356bda4eb3cc734031e24cf00fafcfd32dc76eb5841c7ea8
      "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\n"
      + "6WLAYv7YTVWW4tAR+kg0Eeye7QUd5MjWHYbL",
      //Source URL: https://i.pki.goog/r4.crt
      //Certificate #1 Details:
      //Original Format: DER
      //Subject: CN=GTS Root R4,O=Google Trust Services LLC,C=US
      //Issuer: CN=GTS Root R4,O=Google Trust Services LLC,C=US
      //Expiration Date: 2036-06-22 00:00:00
      //Serial Number: 203E5C068EF631A9C72905052
      //SHA256 Fingerprint: 349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d
      "sha256/MIICCTCCAY6gAwIBAgINAgPlwGjvYxqccpBQUjAKBggqhkjOPQQDAzBHMQswCQYD\n"
      + "VQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIG\n"
      + "A1UEAxMLR1RTIFJvb3QgUjQwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAw\n"
      + "WjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2Vz\n"
      + "IExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwdjAQBgcqhkjOPQIBBgUrgQQAIgNi\n"
      + "AATzdHOnaItgrkO4NcWBMHtLSZ37wWHO5t5GvWvVYRg1rkDdc/eJkTBa6zzuhXyi\n"
      + "QHY7qca4R9gq55KRanPpsXI5nymfopjTX15YhmUPoYRlBtHci8nHc8iMai/lxKvR\n"
      + "HYqjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW\n"
      + "BBSATNbrdP9JNqPV2Py1PsVq8JQdjDAKBggqhkjOPQQDAwNpADBmAjEA6ED/g94D\n"
      + "9J+uHXqnLrmvT/aDHQ4thQEd0dlq7A/Cr8deVl5c1RxYIigL9zC2L7F8AjEA8GE8\n"
      + "p/SgguMh1YQdc4acLa/KNJvxn7kjNuK8YAOdgLOaVsjh4rsUecrNIdSUtUlD",
      //Source URL: https://www.identrust.com/file-download/download/public/5718
      //Certificate #1 Details:
      //Original Format: PKCS7-DER
      //Subject: CN=IdenTrust Commercial Root CA 1,O=IdenTrust,C=US
      //Issuer: CN=IdenTrust Commercial Root CA 1,O=IdenTrust,C=US
      //Expiration Date: 2034-01-16 18:12:23
      //Serial Number: A0142800000014523C844B500000002
      //SHA256 Fingerprint: 5d56499be4d2e08bcfcad08a3e38723d50503bde706948e42f55603019e528ae
      "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",
      //Source URL: https://www.identrust.com/file-download/download/public/5842
      //Certificate #1 Details:
      //Original Format: PKCS7-PEM
      //Subject: CN=IdenTrust Commercial Root TLS ECC CA 2,O=IdenTrust,C=US
      //Issuer: CN=IdenTrust Commercial Root TLS ECC CA 2,O=IdenTrust,C=US
      //Expiration Date: 2039-04-11 21:11:10
      //Serial Number: 40018ECF000DE911D7447B73E4C1F82E
      //SHA256 Fingerprint: 983d826ba9c87f653ff9e8384c5413e1d59acf19ddc9c98cecae5fdea2ac229c
      "sha256/MIICbDCCAc2gAwIBAgIQQAGOzwAN6RHXRHtz5MH4LjAKBggqhkjOPQQDBDBSMQsw\n"
      + "CQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MS8wLQYDVQQDEyZJZGVuVHJ1\n"
      + "c3QgQ29tbWVyY2lhbCBSb290IFRMUyBFQ0MgQ0EgMjAeFw0yNDA0MTEyMTExMTFa\n"
      + "Fw0zOTA0MTEyMTExMTBaMFIxCzAJBgNVBAYTAlVTMRIwEAYDVQQKEwlJZGVuVHJ1\n"
      + "c3QxLzAtBgNVBAMTJklkZW5UcnVzdCBDb21tZXJjaWFsIFJvb3QgVExTIEVDQyBD\n"
      + "QSAyMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBwomiZTgLg8KqEImMmnO5rNPb\n"
      + "Oo9sv5w4nJh45CXs9Gcu8YET9ulxsyVBCVSfSYeppdtXFEWYyBi0QRCAlp5YZHQB\n"
      + "H675v5rWVKRXvhzsuUNi9Xw0Zy1bAXaikmsrY/J0L52j2RulW4q4WvE7f23VFwZu\n"
      + "d82J8k0YG+M4MpmdOho1rsKjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\n"
      + "BAQDAgGGMB0GA1UdDgQWBBQhNGgGrnXhVx/FuQqjXpuH+IlbwzAKBggqhkjOPQQD\n"
      + "BAOBjAAwgYgCQgDc9F4WOxAgci2uQWfsX9cjeIvDXaaeVjDz31Ycc+ZdPrK1JKrB\n"
      + "f6CuTwWy8VojtGxdM3PJMkJC4LGPuhcvkHLo4gJCAV5h+PXe4bDJ3QxE8hkGFoUW\n"
      + "Ak6KtMCIpbLyt5pHrROi+YW9MpScoNGJkg96G1ETvJTWz6dv0uQYjKXt3jlOfQ7g",
      //Source URL: https://ssl-ccp.secureserver.net/repository/sfroot-g2.crt
      //Certificate #1 Details:
      //Original Format: PEM
      //Subject: CN=Starfield Root Certificate Authority - G2,
      // O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
      //Issuer: CN=Starfield Root Certificate Authority - G2,
      // O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
      //Expiration Date: 2037-12-31 23:59:59
      //Serial Number: 0
      //SHA256 Fingerprint: 2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5
      "sha256/MIID3TCCAsWgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCVVMx\n"
      + "EDAO BgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoT\n"
      + "HFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xMjAwBgNVBAMTKVN0YXJmaWVs\n"
      + "ZCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAw\n"
      + "MFoXDTM3MTIzMTIzNTk1OVowgY8xCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6\n"
      + "b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFyZmllbGQgVGVj\n"
      + "aG5vbG9naWVzLCBJbmMuMTIwMAYDVQQDEylTdGFyZmllbGQgUm9vdCBDZXJ0aWZp\n"
      + "Y2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
      + "ggEBAL3twQP89o/8ArFvW59I2Z154qK3A2FWGMNHttfKPTUuiUP3oWmb3ooa/RMg\n"
      + "nLRJdzIpVv257IzdIvpy3Cdhl+72WoTsbhm5iSzchFvVdPtrX8WJpRBSiUZV9Lh1\n"
      + "HOZ/5FSuS/hVclcCGfgXcVnrHigHdMWdSL5stPSksPNkN3mSwOxGXn/hbVNMYq/N\n"
      + "Hwtjuzqd+/x5AJhhdM8mgkBj87JyahkNmcrUDnXMN/uLicFZ8WJ/X7NfZTD4p7dN\n"
      + "dloedl40wOiWVpmKs/B/pM293DIxfJHP4F8R+GuqSVzRmZTRouNjWwl2tVZi4Ut0\n"
      + "HZbUJtQIBFnQmA4O5t78w+wfkPECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAO\n"
      + "BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFHwMMh+n2TB/xH1oo2Kooc6rB1snMA0G\n"
      + "CSqGSIb3DQEBCwUAA4IBAQARWfolTwNvlJk7mh+ChTnUdgWUXuEok21iXQnCoKjU\n"
      + "sHU48TRqneSfioYmUeYs0cYtbpUgSpIB7LiKZ3sx4mcujJUDJi5DnUox9g61DLu3\n"
      + "4jd/IroAow57UvtruzvE03lRTs2Q9GcHGcg8RnoNAX3FWOdt5oUwF5okxBDgBPfg\n"
      + "8n/Uqgr/Qh037ZTlZFkSIHc40zI+OIF1lnP6aI+xy84fxez6nH7PfrHxBy22/L/K\n"
      + "pL/QlwVKvOoYKAKQvVR4CSFx09F9HdkWsKlhPdAKACL8x3vLCWRFCztAgfd9fDL1\n"
      + "mMpYjn0q7pBZc2T5NnReJaH1ZgUufzkVqSr7UIuOhWn0",
  };

  /**
   * Http constructor.
   * @param inMethod The method for the http request
   * @param inHost   The api host provided by Duo and found in the Duo admin panel
   * @param inUri    The endpoint for the request
   * 
   * @deprecated Use the HttpBuilder instead
   */
  public Http(String inMethod, String inHost, String inUri) {
    this(inMethod, inHost, inUri, DEFAULT_TIMEOUT_SECS);
  }

  /**
   * Http constructor.
   * @param inMethod The method for the http request
   * @param inHost   The api host provided by Duo and found in the Duo admin panel
   * @param inUri    The endpoint for the request
   * @param timeout  The timeout for the http request
   * 
   * @deprecated Use the HttpBuilder instead
   */
  protected Http(String inMethod, String inHost, String inUri, int timeout) {
    method = inMethod.toUpperCase();
    host = inHost;
    uri = inUri;

    headers = new Headers.Builder();
    headers.add("Host", host);
    headers.add("user-agent", UserAgentString);

    CertificatePinner pinner = Util.createPinner(host, DEFAULT_CA_CERTS);

    httpClient = new OkHttpClient.Builder()
        .connectTimeout(timeout, TimeUnit.SECONDS)
        .writeTimeout(timeout, TimeUnit.SECONDS)
        .readTimeout(timeout, TimeUnit.SECONDS)
        .certificatePinner(pinner)
        .build();
  }

  /**
   * Executes JSON request.
   *
   * @return The result of the JSON request
   *
   * @throws Exception If the result was not OK
   */
  public Object executeJSONRequest() throws Exception {
    JSONObject result = new JSONObject(executeRequestRaw());
    if (!result.getString("stat").equals("OK")) {
      throw new Exception("Duo error code ("
          + result.get("code").toString()
          + "): "
          + result.getString("message"));
    }
    return result;
  }

  public String executeRequestRaw() throws Exception {
    Response response = executeHttpRequest();
    return response.body().string();
  }

  /**
   * Creates and executes a HTTP request.
   *
   * @return The result of the HTTP request
   *
   * @throws UnsupportedEncodingException For http methods that are not supported
   */
  public Response executeHttpRequest() throws Exception {
    String url = "https://" + host + uri;
    String queryString = canonQueryString();
    String jsonBody = canonJSONBody();
    RequestBody requestBody;
    if (sigVersion == 1 || sigVersion == 2) {
      requestBody = RequestBody.create(queryString, FORM_ENCODED);
    } else if (sigVersion == 5) {
      if ("POST".equals(method) || "PUT".equals(method)) {
        requestBody = RequestBody.create(jsonBody, JSON_ENCODED);
      } else {
        requestBody = null;
      }
    } else {
      throw new UnsupportedOperationException("Unsupported signature version: " + sigVersion);
    }

    Request.Builder requestBuilder = new Request.Builder();
    if (method.equals("POST")) {
      requestBuilder.post(requestBody);
    } else if (method.equals("PUT")) {
      requestBuilder.put(requestBody);
    } else if (method.equals("GET")) {
      if (queryString.length() > 0) {
        url += "?" + queryString;
      }
      requestBuilder.get();
    } else if (method.equals("DELETE")) {
      if (queryString.length() > 0) {
        url += "?" + queryString;
      }
      requestBuilder.delete();
    } else {
      throw new UnsupportedOperationException("Unsupported method: " + method);
    }

    // finish and execute request
    Request request = requestBuilder.headers(headers.build()).url(url).build();
    return executeRequest(request);
  }

  public Object executeRequest() throws Exception {
    JSONObject result = (JSONObject) executeJSONRequest();
    return result.get("response");
  }

  private Response executeRequest(Request request) throws Exception {
    long backoffMs = INITIAL_BACKOFF_MS;
    while (true) {
      Response response = httpClient.newCall(request).execute();
      if (response.code() != RATE_LIMIT_ERROR_CODE || backoffMs > MAX_BACKOFF_MS) {
        return response;
      }

      sleep(backoffMs + nextRandomInt(1000));
      backoffMs *= BACKOFF_FACTOR;
    }
  }

  protected void sleep(long ms) throws Exception {
    Thread.sleep(ms);
  }

  public void signRequest(String ikey, String skey)
      throws UnsupportedEncodingException {
    signRequest(ikey, skey, sigVersion);
  }

  /**
   * Signs Duo request.
   *
   * @param ikey         Integration key provided by Duo and found in the admin
   *                     panel
   * @param skey         Secret key provided by Duo and found in the admin panel
   * @param inSigVersion The version of signature used
   *
   * @throws UnsupportedEncodingException For unsupported encodings
   */
  public void signRequest(String ikey, String skey, int inSigVersion)
      throws UnsupportedEncodingException {
    int[] availableSigVersion = { 1, 2, 5 };

    if (Arrays.stream(availableSigVersion).anyMatch(i -> i == inSigVersion)) {
      sigVersion = inSigVersion;
    }
    String date = formatDate(new Date());
    String canon = canonRequest(date, sigVersion);
    String sig = signHMAC(skey, canon);

    String auth = ikey + ":" + sig;
    String header = "Basic " + Base64.encodeBytes(auth.getBytes());
    addHeader("Authorization", header);
    if (sigVersion == 2 || sigVersion == 5) {
      addHeader("Date", date);
    }
  }

  protected String signHMAC(String skey, String msg) {
    try {
      byte[] sigBytes = Util.hmac(signingAlgorithm,
          skey.getBytes(),
          msg.getBytes());
      String sig = Util.bytes_to_hex(sigBytes);
      return sig;
    } catch (Exception e) {
      return "";
    }
  }

  private String formatDate(Date date) {
    // Could use ThreadLocal or a pool of format objects instead
    // depending on the needs of the application.
    synchronized (RFC_2822_DATE_FORMAT) {
      return RFC_2822_DATE_FORMAT.format(date);
    }
  }

  public void addHeader(String name, String value) {
    headers.add(name, value);
  }

  public void addParam(String name, String value) {
    params.put(name, value);
  }

  public void addParam(String name, Integer value) {
    params.put(name, value);
  }

  public void addParam(String name, JSONObject value) {
    params.put(name, value);
  }

  public void addParam(String name, List<Object> value) {
    params.put(name, value);
  }

  public void addAdditionalDuoHeader(Map<String, String> inAdditionalDuoHeaders) {
    additionalDuoHeaders.putAll(inAdditionalDuoHeaders);
  }

  /**
   * Creates a new proxy.
   *
   * @param host The proxy host
   * @param port The port of the proxy
   */
  public void setProxy(String host, int port) {
    Proxy httpProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    httpClient = httpClient.newBuilder().proxy(httpProxy).build();
  }

  /**
   * Use custom CA certificates for certificate pinning.
   *
   * @param customCaCerts The CA certificates to pin
   */
  public void useCustomCertificates(String[] customCaCerts) {
    CertificatePinner pinner = Util.createPinner(host, customCaCerts);
    httpClient = httpClient.newBuilder().certificatePinner(pinner).build();
  }

  protected String canonRequest(String date, int sigVersion)
      throws UnsupportedEncodingException {
    String canon = "";
    String canonParam;
    String canonBody;
    if (sigVersion == 1) {
      canon += method.toUpperCase() + "\n";
      canon += host.toLowerCase() + "\n";
      canon += uri + "\n";
      canon += canonQueryString();
    } else if (sigVersion == 2) {
      canon += date + "\n";
      canon += method.toUpperCase() + "\n";
      canon += host.toLowerCase() + "\n";
      canon += uri + "\n";
      canon += canonQueryString();
    } else if (sigVersion == 5) {
      canon += date + "\n";
      canon += method.toUpperCase() + "\n";
      canon += host.toLowerCase() + "\n";
      canon += uri + "\n";
      if ("POST".equals(method) || "PUT".equals(method)) {
        canonParam = "\n";
        canonBody = Util.bytes_to_hex(Util.hash(hashingAlgorithm, canonJSONBody()));
      } else {
        canonParam = canonQueryString() + "\n";
        canonBody = Util.bytes_to_hex(Util.hash(hashingAlgorithm, ""));
      }
      canon += canonParam;
      canon += canonBody + "\n";
      canon += Util.bytes_to_hex(Util.hash(hashingAlgorithm, canonXDuoHeaders()));
    }

    return canon;
  }

  private String canonQueryString()
      throws UnsupportedEncodingException {
    ArrayList<String> args = new ArrayList<String>();

    for (String key : params.keySet()) {
      String name = URLEncoder
          .encode(key, "UTF-8")
          .replace("+", "%20")
          .replace("*", "%2A")
          .replace("%7E", "~");
      String value = URLEncoder
          .encode(params.get(key).toString(), "UTF-8")
          .replace("+", "%20")
          .replace("*", "%2A")
          .replace("%7E", "~");
      args.add(name + "=" + value);
    }

    return Util.join(args.toArray(), "&");
  }

  private String canonJSONBody() {
    JSONObject jsonBody = new JSONObject(params);
    return jsonBody.toString();
  }

  private String canonXDuoHeaders() {
    List<String> canonList = new ArrayList<>();
    for (String name : additionalDuoHeaders.keySet()) {
      String value = additionalDuoHeaders.get(name);
      canonList.add(name + Character.MIN_VALUE + value);
      headers.add(name, value);
    }
    return Util.join(canonList.toArray(), String.valueOf(Character.MIN_VALUE));
  }

  public int nextRandomInt(int bound) {
    return random.nextInt(bound);
  }

  public static class HttpBuilder extends ClientBuilder<Http> {
    /**
     * Builder entry point.
     *
     * @param method the HTTP method to use
     * @param host   the Duo host
     * @param uri    the API endpoint for the request
     */
    protected HttpBuilder(String method, String host, String uri) {
      super(method, host, uri);
    }

    @Override
    protected Http createClient(String method, String host, String uri, int timeout) {
      return new Http(method, host, uri, timeout);
    }
  }

  /**
   * Builder for an Http client object.
   */
  protected abstract static class ClientBuilder<T extends Http> {
    private final String method;
    private final String host;
    private final String uri;

    private int timeout = DEFAULT_TIMEOUT_SECS;
    private String[] caCerts = null;
    private SortedMap<String, String> additionalDuoHeaders = new TreeMap<String, String>();
    private Map<String, String> headers = new HashMap<String, String>();

    /**
     * Builder entry point.
     *
     * @param method the HTTP method to use
     * @param host   the Duo host
     * @param uri    the API endpoint for the request
     */
    public ClientBuilder(String method, String host, String uri) {
      this.method = method;
      this.host = host;
      this.uri = uri;
    }

    /**
     * Set a custom timeout for HTTP calls.
     *
     * @param timeout the timeout to use
     * @return the Builder
     */
    public ClientBuilder<T> useTimeout(int timeout) {
      this.timeout = timeout;

      return this;
    }

    /**
     * Provide custom CA certificates for certificate pinning.
     *
     * @param customCaCerts The CA certificates to pin to
     * @return the Builder
     */
    public ClientBuilder<T> useCustomCertificates(String[] customCaCerts) {
      this.caCerts = customCaCerts;

      return this;
    }

    /**
     * Set additional x-duo header for the HTTP client.
     *
     * @param name  Header's name
     * @param value Header's value
     * @return the Builder
     */
    public ClientBuilder<T> addAdditionalDuoHeader(String name, String value) 
        throws IllegalArgumentException {
      validateXDuoHeader(name, value);
      this.additionalDuoHeaders.put(name.toLowerCase(), value);
      return this;

    }

    /**
     * Add header for the HTTP client.
     *
     * @param name  Header's name
     * @param value Header's value
     * @return the Builder
     */
    public ClientBuilder<T> addHeader(String name, String value) {
      this.headers.put(name, value);
      return this;
    }

    /**
     * Build the HTTP client object based on the builder options.
     *
     * @return the specified Http client object
     */
    public T build() {
      T duoClient = createClient(method, host, uri, timeout);
      if (caCerts != null) {
        duoClient.useCustomCertificates(caCerts);
      }
      if (additionalDuoHeaders != null) {
        duoClient.addAdditionalDuoHeader(additionalDuoHeaders);
      }
      if (headers != null) {
        for (String name : headers.keySet()) {
          String value = headers.get(name);
          duoClient.addHeader(name, value);
        }
      }

      return duoClient;
    }

    protected abstract T createClient(String method, String host, String uri, int timeout);

    private void validateXDuoHeader(String name, String value) throws IllegalArgumentException {
      if (name == null || name.length() == 0) {
        throw new IllegalArgumentException("Not allowed 'Null' or empty header name");
      } else if (value == null || value.length() == 0) {
        throw new IllegalArgumentException("Not allowed 'Null' or empty header value");
      } else if (!name.toLowerCase().startsWith("x-duo-")) {
        throw new IllegalArgumentException("Additional headers must start with \'X-Duo-\'");
      } else if (additionalDuoHeaders.containsKey(name)) {
        throw new IllegalArgumentException("Duplicate header passed, header=" + name);
      }
    }
  }
}
