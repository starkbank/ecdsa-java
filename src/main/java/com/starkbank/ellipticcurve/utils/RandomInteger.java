package com.starkbank.ellipticcurve.utils;

import com.starkbank.ellipticcurve.Curve;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public class RandomInteger {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Return integer x in the range: start <= x <= end
     *
     * @param start minimum value of the integer
     * @param end maximum value of the integer
     * @return BigInteger
     */
    public static BigInteger between(BigInteger start, BigInteger end) {
        BigInteger range = end.subtract(start).add(BigInteger.ONE);
        int bits = range.bitLength();
        BigInteger result;
        do {
            result = new BigInteger(bits, secureRandom);
        } while (result.compareTo(range) >= 0);
        return result.add(start);
    }

    /**
     * Generate deterministic nonce values per RFC 6979
     *
     * @param hashBytes the hash of the message
     * @param secret the private key secret
     * @param curve the curve
     * @param algorithm the HMAC algorithm name (e.g., "HmacSHA256")
     * @return an iterator of candidate k values
     */
    public static Iterator<BigInteger> rfc6979(byte[] hashBytes, BigInteger secret, Curve curve, String algorithm) {
        int orderBitLen = curve.N.bitLength();
        int orderByteLen = (orderBitLen + 7) / 8;

        // Secret bytes, zero-padded to orderByteLen
        byte[] secretBytes = bigIntToFixedBytes(secret, orderByteLen);

        // Hash reduced mod N, then zero-padded to orderByteLen
        BigInteger hashReduced = numberFromByteString(hashBytes, orderBitLen).mod(curve.N);
        byte[] hashOctets = bigIntToFixedBytes(hashReduced, orderByteLen);

        int hLen = getHmacLength(algorithm);

        byte[] V = new byte[hLen];
        Arrays.fill(V, (byte) 0x01);
        byte[] K = new byte[hLen];
        Arrays.fill(K, (byte) 0x00);

        // K = HMAC(K, V || 0x00 || secretBytes || hashOctets)
        K = hmac(algorithm, K, concat(V, new byte[]{0x00}, secretBytes, hashOctets));
        V = hmac(algorithm, K, V);
        // K = HMAC(K, V || 0x01 || secretBytes || hashOctets)
        K = hmac(algorithm, K, concat(V, new byte[]{0x01}, secretBytes, hashOctets));
        V = hmac(algorithm, K, V);

        final byte[] finalK = K;
        final byte[] finalV = V;
        final BigInteger curveN = curve.N;
        final String algo = algorithm;
        final int bitLen = orderBitLen;

        return new Iterator<BigInteger>() {
            private byte[] k = finalK;
            private byte[] v = finalV;

            @Override
            public boolean hasNext() {
                return true;
            }

            @Override
            public BigInteger next() {
                while (true) {
                    byte[] T = new byte[0];
                    while (T.length * 8 < bitLen) {
                        v = hmac(algo, k, v);
                        T = concat(T, v);
                    }

                    BigInteger candidate = numberFromByteString(T, bitLen);

                    if (candidate.compareTo(BigInteger.ONE) >= 0 && candidate.compareTo(curveN.subtract(BigInteger.ONE)) <= 0) {
                        // Prepare for next call
                        k = hmac(algo, k, concat(v, new byte[]{0x00}));
                        v = hmac(algo, k, v);
                        return candidate;
                    }

                    k = hmac(algo, k, concat(v, new byte[]{0x00}));
                    v = hmac(algo, k, v);
                }
            }

            @Override
            public void remove() {
                throw new UnsupportedOperationException();
            }
        };
    }

    public static BigInteger numberFromByteString(byte[] bytes, int bitLength) {
        BigInteger number = new BigInteger(1, bytes);
        int hashBitLen = bytes.length * 8;
        if (bitLength > 0 && hashBitLen > bitLength) {
            number = number.shiftRight(hashBitLen - bitLength);
        }
        return number;
    }

    private static byte[] bigIntToFixedBytes(BigInteger value, int length) {
        String hex = value.toString(16);
        while (hex.length() < length * 2) {
            hex = "0" + hex;
        }
        return hexToBytes(hex);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    static byte[] hmac(String algorithm, byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC computation failed", e);
        }
    }

    static byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] a : arrays) totalLen += a.length;
        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, offset, a.length);
            offset += a.length;
        }
        return result;
    }

    private static int getHmacLength(String algorithm) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(new byte[1], algorithm));
            return mac.getMacLength();
        } catch (Exception e) {
            throw new RuntimeException("Could not determine HMAC length for " + algorithm, e);
        }
    }
}
