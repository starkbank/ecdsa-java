package com.github.starkbank.ellipticcurve;

import java.math.BigInteger;

/**
 * Created on 07-Jan-19
 * @author Taron Petrosyan
 */
public class Point {
    public BigInteger x;

    public BigInteger y;

    public BigInteger z;

    public Point(BigInteger x) {
        this.x = x;
        this.y = BigInteger.ZERO;
        this.z = BigInteger.ZERO;
    }

    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
        this.z = BigInteger.ZERO;
    }

    public Point(BigInteger x, BigInteger y, BigInteger z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    public Point(long x, long y) {
        this(BigInteger.valueOf(x), BigInteger.valueOf(y));
    }
}
