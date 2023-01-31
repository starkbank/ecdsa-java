package com.starkbank.ellipticcurve.utils;
import java.math.BigInteger;
import java.util.Base64;

public class Binary {

    static public String hexFromInt(BigInteger number) {
        String hexadecimal = number.toString(16);
        if (hexadecimal.length() % 2 != 0) {
            hexadecimal = "0" + hexadecimal;
        }
        return hexadecimal;
    }

    static public String hexFromInt(int number) {
        String hexadecimal = Integer.toHexString(number);
        if (hexadecimal.length() % 2 != 0) {
            hexadecimal = "0" + hexadecimal;
        }
        return hexadecimal;
    }

    static public String hexFromInt(long number) {
        return hexFromInt((int) number);
    }

    static public BigInteger intFromHex(String hexadecimal) {
        return new BigInteger(hexadecimal, 16);
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    static public String hexFromByte(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    static public byte[] byteFromHex(String hexadecimal) {
        int hexLength = hexadecimal.length();
        if (hexLength % 2 != 0) {
            throw new IllegalArgumentException("Hexadecimal string must have an even number of characters");
        }

        byte[] retBuf = new byte[hexLength / 2];

        for (int i = 0; i < hexLength; i += 2) {
            int top = Character.digit(hexadecimal.charAt(i), 16);
            int bottom = Character.digit(hexadecimal.charAt(i + 1), 16);
            if (top == -1 || bottom == -1) {
                throw new IllegalArgumentException("Hexadecimal string contains non-hexadecimal characters");
            }
            retBuf[i / 2] = (byte) ((top << 4) + bottom);
        }

        return retBuf;
    }

    static public String base64FromByte(byte[] byteString) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(byteString);
    }

    static public byte[] byteFromBase64(String base64) {
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(base64);
    }

    static public String bitsFromHex(String hex) {
        String binary = intFromHex(hex).toString(2);
        binary = padLeftZeros(binary, 4 * hex.length());
        return binary;
    }

    static public String bitsFromHex(char hex) {
        String binary = intFromHex(String.valueOf(hex)).toString(2);
        binary = padLeftZeros(binary, 4 * String.valueOf(hex).length());
        return binary;
    }

    static public String padLeftZeros(String inputString, int length) {
        if (inputString.length() >= length) {
            return inputString;
        }
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append('0');
        }
        sb.append(inputString);
    
        return sb.toString();
    }

    public static long[] longFromString(String s) {
        String[] test = s.substring(s.indexOf("[") + 1, s.indexOf("]")).split(", ");
        long[] oid = new long[test.length];
        for (int i = 0; i < test.length; i++) {
            oid[i] = Long.parseLong(test[i]);
        }
        return oid;
    }

    public static BigInteger numberFromString(byte[] string) {
        return new BigInteger(Binary.hexFromByte(string), 16);
    }
}
