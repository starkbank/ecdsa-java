package com.github.starkbank.ellipticcurve;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import static com.github.starkbank.ellipticcurve.Math.*;

/**
 * Created on 05-Jan-19
 *
 * @author Taron Petrosyan
 */
public final class Ecdsa {
    private Ecdsa() {
        throw new UnsupportedOperationException("Ecdsa is a utility class and cannot be instantiated");
    }

    public static Signature sign(String message, PrivateKey privateKey, MessageDigest hashfunc) {
        String hashMessage = new String(hashfunc.digest(message.getBytes()));
        BigInteger numberMessage = numberFrom(hashMessage);
        Curve curve = privateKey.curve;
        Random random = new SecureRandom();
        BigInteger randNum = new BigInteger(curve.n.toByteArray().length * 8 - 1, random);
        Point randomSignPoint = multiply(new Point(curve.gX, curve.gY), randNum, curve.n, curve.a, curve.p);
        BigInteger r = randomSignPoint.x.mod(curve.n);
        BigInteger s = ((numberMessage.add(r.multiply(privateKey.secret))).multiply(inv(randNum, curve.n))).mod(curve.n);
        return new Signature(r, s);
    }

    public static Signature sign(String message, PrivateKey privateKey) {
        try {
            return sign(message, privateKey, MessageDigest.getInstance("SHA-256"));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not find SHA-256 message digest in provided java environment");
        }
    }

    public static boolean verify(String message, Signature signature, PublicKey publicKey, MessageDigest hashfunc) {
        String hashMessage = new String(hashfunc.digest(message.getBytes()));
        BigInteger numberMessage = numberFrom(hashMessage);
        Curve curve = publicKey.curve;
        BigInteger Xpk = publicKey.x;
        BigInteger Ypk = publicKey.y;
        BigInteger r = signature.r;
        BigInteger s = signature.s;
        BigInteger w = inv(s, curve.n);
        Point u1 = multiply(new Point(curve.gX, curve.gY), numberMessage.multiply(w).mod(curve.n), curve.n, curve.a, curve.p);
        Point u2 = multiply(new Point(Xpk, Ypk), r.multiply(w).mod(curve.n), curve.n, curve.a, curve.p);
        Point point = add(u1, u2, curve.a, curve.p);
        return r.compareTo(point.x) == 0;
    }

    public static boolean verify(String message, Signature signature, PublicKey publicKey) {
        try {
            return verify(message, signature, publicKey, MessageDigest.getInstance("SHA-256"));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not find SHA-256 message digest in provided java environment");
        }
    }
}
