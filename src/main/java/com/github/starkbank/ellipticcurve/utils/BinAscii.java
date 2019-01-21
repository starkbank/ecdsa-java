package com.github.starkbank.ellipticcurve.utils;

import com.github.starkbank.ellipticcurve.ByteString;

import java.math.BigInteger;
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

    public static byte[] toBytes(int c) {
        return new byte[]{(byte) c};
    }

}
