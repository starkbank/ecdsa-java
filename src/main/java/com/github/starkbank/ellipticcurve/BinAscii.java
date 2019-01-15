package com.github.starkbank.ellipticcurve;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * Created on 12-Jan-19
 *
 * @author Taron Petrosyan
 */
public final class BinAscii {

    private BinAscii() {
        throw new UnsupportedOperationException("BinAscii is a utility class and cannot be instantiated");
    }

    public static String hexlify(String string) {
        byte[] bytes = string.getBytes();
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

    public static String unhexlify(String string) {
//        byte[] bytes = new byte[string.length() / 2];
//
//        for (int i = 0; i < string.length(); i += 2) {
//            bytes[i/2] = Byte.valueOf(string.substring(i, i + 2), 16);
//        }
        return new String(new BigInteger(string, 16).toByteArray());
    }

    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE/8);
        buffer.putLong(x);
        return buffer.array();
    }

}
