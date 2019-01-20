package com.github.starkbank.ellipticcurve;

import java.math.BigInteger;
import java.util.*;

/**
 * Elliptic Curve Equation.
 * y^2 = x^3 + a*x + b (mod p)
 * Created on 05-Jan-19
 *
 * @author Taron Petrosyan
 */

@SuppressWarnings("unchecked")
public class Curve {

    public static class OID {
        private long[] oid;

        public OID(long[] oid) {
            this.oid = oid;
        }

        public long[] getOid() {
            return oid;
        }

        public void setOid(long[] oid) {
            this.oid = oid;
        }

        @Override
        public String toString() {
            return "OID{" +
                    "oid=" + Arrays.toString(oid) +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof OID)) return false;

            OID oid1 = (OID) o;

            return Arrays.equals(oid, oid1.oid);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(oid);
        }
    }

    public static final Curve secp256k1 = new Curve(
            BigInteger.ZERO,
            BigInteger.valueOf(7),
            new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
            new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
            new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
            new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
            "secp256k1",
            new OID(new long[]{1, 3, 132, 0, 10})
    );

    //List<Curve>
    public static final List supportedCurves = new ArrayList();

    // Map<BigInteger[], Curve>
    public static final Map curvesByOid = new HashMap();

    static {
        supportedCurves.add(secp256k1);

        for (Object c : supportedCurves) {
            Curve curve = (Curve) c;
            curvesByOid.put(curve.oid, curve);
        }
    }

    public BigInteger a;
    public BigInteger b;
    public BigInteger p;
    public BigInteger n;
    public BigInteger gX;
    public BigInteger gY;
    public String name;
    public OID oid;

    public Curve(BigInteger a, BigInteger b, BigInteger p, BigInteger n, BigInteger gX, BigInteger gY, String name, OID oid) {
        this.a = a;
        this.b = b;
        this.p = p;
        this.n = n;
        this.gX = gX;
        this.gY = gY;
        this.name = name;
        this.oid = oid;
    }

    /**
     * Is the point R(x,y) on this curve
     *
     * @param x point's ordinate
     * @param y point's abscissa
     * @return true if point is in the curve otherwise false
     */
    public boolean contains(BigInteger x, BigInteger y) {
        return y.pow(2).subtract(x.pow(3).add(a.multiply(x)).add(b)).mod(p).intValue() == 0;
    }

    public int length() {
        return (1 + n.toString(16).length()) / 2;
    }

    @Override
    public String toString() {
        return "Curve{" +
                "name='" + name + '\'' +
                ", oid=" + oid.toString() +
                '}';
    }
}
