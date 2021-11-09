package com.starkbank.ellipticcurve;
import java.math.BigInteger;
import java.util.*;

/**
 * Elliptic Curve Equation.
 * y^2 = x^3 + A*x + B (mod P)
 *
 */

public class Curve {

    public BigInteger A;
    public BigInteger B;
    public BigInteger P;
    public BigInteger N;
    public Point G;
    public String name;
    public long[] oid;

    /**
     *
     * @param A A
     * @param B B
     * @param P P
     * @param N N
     * @param Gx Gx
     * @param Gy Gy
     * @param name name
     * @param oid oid
     */
    public Curve(BigInteger A, BigInteger B, BigInteger P, BigInteger N, BigInteger Gx, BigInteger Gy, String name, long[] oid) {
        this.A = A;
        this.B = B;
        this.P = P;
        this.N = N;
        this.G = new Point(Gx, Gy);
        this.name = name;
        this.oid = oid;
    }

    /**
     * Verify if the point `p` is on the curve
     *
     * @param p Point p = Point(x, y)
     * @return true if point is in the curve otherwise false
     */
    public boolean contains(Point p) {
        return p.y.pow(2).subtract(p.x.pow(3).add(A.multiply(p.x)).add(B)).mod(P).intValue() == 0;
    }

    /**
     *
     * @return int
     */
    public int length() {
        return (1 + N.toString(16).length()) / 2;
    }

    /**
     *
     */
    public static final Curve secp256k1 = new Curve(
        BigInteger.ZERO,
        BigInteger.valueOf(7),
        new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
        new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
        new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
        new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
        "secp256k1",
        new long[]{1, 3, 132, 0, 10}
    );

    /**
     *
     */
    public static final List supportedCurves = new ArrayList();

    /**
     *
     */
    public static final Map curvesByOid = new HashMap();

    static {
        supportedCurves.add(secp256k1);

        for (Object c : supportedCurves) {
            Curve curve = (Curve) c;
            curvesByOid.put(Arrays.hashCode(curve.oid), curve);
        }
    }
}
