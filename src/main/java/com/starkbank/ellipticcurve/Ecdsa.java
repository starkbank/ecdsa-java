package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.Binary;
import com.starkbank.ellipticcurve.utils.RandomInteger;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class Ecdsa {

    /**
     *
     * @param message message
     * @param privateKey privateKey
     * @param hashfunc hashfunc
     * @return Signature
     */
    public static Signature sign(String message, PrivateKey privateKey, MessageDigest hashfunc) {
        byte[] byteMessage = hashfunc.digest(message.getBytes());
        BigInteger numberMessage = Binary.numberFromString(byteMessage);
        Curve curve = privateKey.curve;

        BigInteger r = BigInteger.ZERO;
        BigInteger s = BigInteger.ZERO;
        Point randomSignPoint = null;
        while(r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO)) {
            BigInteger randNum = RandomInteger.between(BigInteger.ONE, curve.N.subtract(BigInteger.ONE));
            randomSignPoint = Math.multiply(curve.G, randNum, curve.N, curve.A, curve.P);
            r = randomSignPoint.x.mod(curve.N);
            s = ((numberMessage.add(r.multiply(privateKey.secret))).multiply(Math.inv(randNum, curve.N))).mod(curve.N);
        }
        BigInteger recoveryId = randomSignPoint.y.and(BigInteger.ONE);
        if (randomSignPoint.y.compareTo(curve.N) > 0){
            recoveryId = recoveryId.add(BigInteger.valueOf(2));
        }

        return new Signature(r, s, recoveryId);
    }

    /**
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
     *
     * @param message message
     * @param signature signature
     * @param publicKey publicKey
     * @param hashfunc hashfunc
     * @return boolean
     */
    public static boolean verify(String message, Signature signature, PublicKey publicKey, MessageDigest hashfunc) {
        byte[] byteMessage = hashfunc.digest(message.getBytes());
        BigInteger numberMessage = Binary.numberFromString(byteMessage);
        Curve curve = publicKey.curve;
        BigInteger r = signature.r;
        BigInteger s = signature.s;

        if (r.compareTo(BigInteger.ONE) < 0) {
            return false;
        }
        if (r.compareTo(curve.N) >= 0) {
            return false;
        }
        if (s.compareTo(BigInteger.ONE) < 0) {
            return false;
        }
        if (s.compareTo(curve.N) >= 0) {
            return false;
        }
        
        BigInteger inv = Math.inv(s, curve.N);
        Point u1 = Math.multiply(curve.G, numberMessage.multiply(inv).mod(curve.N), curve.N, curve.A, curve.P);
        Point u2 = Math.multiply(publicKey.point, r.multiply(inv).mod(curve.N), curve.N, curve.A, curve.P);
        Point v = Math.add(u1, u2, curve.A, curve.P);
        if (v.isAtInfinity()) {
            return false;
        }
        return v.x.mod(curve.N).equals(r);
    }

    /**
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
}
