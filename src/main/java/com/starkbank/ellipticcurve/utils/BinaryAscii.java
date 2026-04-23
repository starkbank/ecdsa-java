package com.starkbank.ellipticcurve.utils;
import java.math.BigInteger;
import java.util.Arrays;


public final class BinaryAscii {

    /**
     * @param string byteString
     * @return String
     */
    public static String hexFromBinary(ByteString string) {
        return hexFromBinary(string.getBytes());
    }

    /**
     * @param bytes byte[]
     * @return String
     */
    public static String hexFromBinary(byte[] bytes) {
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

    /**
     * @param string string
     * @return byte[]
     */
    public static byte[] binaryFromHex(String string) {
        if (string.length() % 2 != 0) {
            string = "0" + string;
        }
        int len = string.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4)
                    + Character.digit(string.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * @param c c
     * @return byte[]
     */
    public static byte[] toBytes(int c) {
        return new byte[]{(byte) c};
    }

    /**
     * Get a number representation of a byte array
     *
     * @param string byte[] to be converted to a number
     * @return BigInteger
     */
    public static BigInteger numberFromString(byte[] string) {
        return new BigInteger(1, string);
    }

    /**
     * Get a string representation of a number
     *
     * @param number number to be converted in a string
     * @param length length max number of bytes for the string
     * @return ByteString
     */
    public static ByteString stringFromNumber(BigInteger number, int length) {
        String fmtStr = "%0" + String.valueOf(2 * length) + "x";
        String hexString = String.format(fmtStr, number);
        return new ByteString(binaryFromHex(hexString));
    }
}
