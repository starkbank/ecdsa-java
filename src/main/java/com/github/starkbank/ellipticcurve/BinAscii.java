package com.github.starkbank.ellipticcurve;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Created on 12-Jan-19
 *
 * @author Taron Petrosyan
 */
public final class BinAscii {

    private BinAscii() {
        throw new UnsupportedOperationException("BinAscii is a utility class and cannot be instantiated");
    }

    private static String hexlify(String string) {
        byte[] bytes;
        try {
            bytes = string.getBytes("US-ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Unsupported non ASCII string");
        }
        return hexlify(bytes);
    }

    public static String hexlify(ByteString string) {
        return hexlify(string.getBytes());
    }

    public static String hexlify(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();

        for (byte aByte : bytes) {
            String hex = Integer.toHexString(0xFF & aByte);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] unhexlify(String string) {
        byte[] bytes = new BigInteger(string, 16).toByteArray();
        int i = 0;
        while (i < bytes.length && bytes[i] == 0) {
            i++;
        }
        return Arrays.copyOfRange(bytes, i, bytes.length);
    }

}
