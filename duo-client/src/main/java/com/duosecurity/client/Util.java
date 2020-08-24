package com.duosecurity.client;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Util {
  /**
   * Creates a hmac of textBytes.
   *
   * @param algorithm   The algorithm used to create the hmac
   * @param keyBytes    The key used to initialize the hmac
   * @param textBytes   The text in bytes used to create the hmac
   *
   * @return The hmac of testBytes
   *
   * @throws NoSuchAlgorithmException For invalid algorithms
   * @throws InvalidKeyException      For invalid keys
   */
  public static byte[] hmac(String algorithm, byte[] keyBytes, byte[] textBytes)
      throws NoSuchAlgorithmException, InvalidKeyException {
    Mac hmac = Mac.getInstance(algorithm);
    SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
    hmac.init(macKey);
    return hmac.doFinal(textBytes);
  }

  /**
   * Changes bytes to hex.
   *
   * @param b    Byte array to be changed to a hex string
   *
   * @return     The hex string of b
   */
  public static String bytes_to_hex(byte[] b) {
    String result = "";
    for (int i = 0; i < b.length; i++) {
      result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
    }
    return result;
  }

  /**
   * Join elements from s together to make a string.
   *
   * @param s       An object that will be joined to make a string
   * @param joiner  A string used to join the elements of s together
   *
   * @return        The string made from joining elements of s and the joiner
   */
  public static String join(Object[] s, String joiner) {
    int itemCount = s.length;
    if (itemCount == 0) {


      return "";
    }

    StringBuilder out = new StringBuilder();
    out.append(s[0]);

    for (int x = 1; x < itemCount; x++) {
      String item = (String) s[x];
      if (!"".equals(item)) {
        out.append(joiner).append(item);
      }
    }

    return out.toString();
  }
}
