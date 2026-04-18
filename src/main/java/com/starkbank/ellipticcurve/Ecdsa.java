package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.RandomInteger;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;


public class Ecdsa {

    /**
     * Sign a message using the private key with a specified hash function.
     *
     * @param message message
     * @param privateKey privateKey
     * @param hashfunc hashfunc
     * @return Signature
     */
    public static Signature sign(String message, PrivateKey privateKey, MessageDigest hashfunc) {
        Curve curve = privateKey.curve;
        byte[] byteMessage = hashfunc.digest(message.getBytes(StandardCharsets.UTF_8));
        BigInteger numberMessage = RandomInteger.numberFromByteString(byteMessage, curve.nBitLength);

        String hmacAlgorithm = getHmacAlgorithm(hashfunc.getAlgorithm());
        Iterator<BigInteger> kIterator = RandomInteger.rfc6979(byteMessage, privateKey.secret, curve, hmacAlgorithm);

        BigInteger r = BigInteger.ZERO, s = BigInteger.ZERO;
        Point randSignPoint = null;
        while (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO)) {
            BigInteger randNum = kIterator.next();
            randSignPoint = Math.multiplyGenerator(curve, randNum);
            r = randSignPoint.x.mod(curve.N);
            s = numberMessage.add(r.multiply(privateKey.secret)).multiply(Math.inv(randNum, curve.N)).mod(curve.N);
        }

        int recoveryId = randSignPoint.y.testBit(0) ? 1 : 0;
        if (randSignPoint.y.compareTo(curve.N) > 0) {
            recoveryId += 2;
        }
        // Low-S normalization
        BigInteger halfN = curve.N.shiftRight(1);
        if (s.compareTo(halfN) > 0) {
            s = curve.N.subtract(s);
            recoveryId ^= 1;
        }

        return new Signature(r, s, recoveryId);
    }

    /**
     * Sign a message using the private key with SHA-256.
     *
     * @param message message
     * @param privateKey privateKey
     * @return Signature
     */
    public static Signature sign(String message, PrivateKey privateKey) {
        try {
            return sign(message, privateKey, MessageDigest.getInstance("SHA-256"));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not find SHA-256 message digest in provided java environment");
        }
    }

    /**
     * Verify a signature against a message and public key with a specified hash function.
     *
     * @param message message
     * @param signature signature
     * @param publicKey publicKey
     * @param hashfunc hashfunc
     * @return boolean
     */
    public static boolean verify(String message, Signature signature, PublicKey publicKey, MessageDigest hashfunc) {
        Curve curve = publicKey.curve;
        byte[] byteMessage = hashfunc.digest(message.getBytes(StandardCharsets.UTF_8));
        BigInteger numberMessage = RandomInteger.numberFromByteString(byteMessage, curve.nBitLength);
        BigInteger r = signature.r;
        BigInteger s = signature.s;

        if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(curve.N.subtract(BigInteger.ONE)) > 0) {
            return false;
        }
        if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(curve.N.subtract(BigInteger.ONE)) > 0) {
            return false;
        }
        if (!curve.contains(publicKey.point)) {
            return false;
        }

        BigInteger inv = Math.inv(s, curve.N);
        Point v = Math.multiplyAndAdd(
            curve.G, numberMessage.multiply(inv).mod(curve.N),
            publicKey.point, r.multiply(inv).mod(curve.N),
            curve.N, curve.A, curve.P
        );
        if (v.isAtInfinity()) {
            return false;
        }
        return v.x.mod(curve.N).equals(r);
    }

    /**
     * Verify a signature against a message and public key with SHA-256.
     *
     * @param message message
     * @param signature signature
     * @param publicKey publicKey
     * @return boolean
     */
    public static boolean verify(String message, Signature signature, PublicKey publicKey) {
        try {
            return verify(message, signature, publicKey, MessageDigest.getInstance("SHA-256"));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not find SHA-256 message digest in provided java environment");
        }
    }

    /**
     * Convert a MessageDigest algorithm name to the corresponding HMAC algorithm name.
     */
    private static String getHmacAlgorithm(String digestAlgorithm) {
        // MessageDigest names like "SHA-256" -> "HmacSHA256"
        String normalized = digestAlgorithm.replace("-", "");
        return "Hmac" + normalized;
    }
}
