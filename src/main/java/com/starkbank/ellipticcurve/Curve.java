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
    public String nistName;
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
     * @param nistName nistName
     * @param oid oid
     */
    public Curve(
        BigInteger A, BigInteger B, BigInteger P, BigInteger N, BigInteger Gx, 
        BigInteger Gy, String name, String nistName, long[] oid
    ) {
        this.A = A;
        this.B = B;
        this.P = P;
        this.N = N;
        this.G = new Point(Gx, Gy);
        this.name = name;
        this.nistName = nistName;
        this.oid = oid;
    }

    public Curve(
        BigInteger A, BigInteger B, BigInteger P, BigInteger N, BigInteger Gx, 
        BigInteger Gy, String name, long[] oid
    ) {
        this(A, B, P, N, Gx, Gy, name, null, oid);
    }

    /**
     * Verify if the point `p` is on the curve
     *
     * @param p Point p = Point(x, y)
     * @return true if point is in the curve otherwise false
     */
    public boolean contains(Point p) {
        if (p.x.compareTo(BigInteger.ZERO) < 0) {
            return false;
        }
        if (p.x.compareTo(this.P) >= 0) {
            return false;
        }
        if (p.y.compareTo(BigInteger.ZERO) < 0) {
            return false;
        }
        if (p.y.compareTo(this.P) >= 0) {
            return false;
        }
        return p.y.pow(2).subtract(p.x.pow(3).add(A.multiply(p.x)).add(B)).mod(P).intValue() == 0;
    }

    /**
     *
     * @return int
     */
    public int length() {
        return (1 + N.toString(16).length()) / 2;
    }

    public BigInteger y(BigInteger x, Boolean isEven) {
        BigInteger ySquared = (x.modPow(BigInteger.valueOf(3), this.P).add(this.A.multiply(x)).add(this.B)).mod(this.P);
        BigInteger y = Math.modularSquareRoot(ySquared, this.P);
        if (isEven != y.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            return y = this.P.subtract(y);
        }
        return y;
    }

    public static final Map<Integer, Curve> curvesByOid = new HashMap<Integer, Curve>();

    public static void add(Curve curve) {
        curvesByOid.put(Arrays.hashCode(curve.oid), curve);
    }

    public static Curve getByOid(long[] oid) {
        String[] names = new String[curvesByOid.size()];
        for (int i = 0; i < names.length; i++) {
            names[i] = ((Curve) curvesByOid.values().toArray()[i]).name;
        }
        if(!curvesByOid.containsKey(Arrays.hashCode(oid))) {
            throw new Error("Unknown curve with oid " + Arrays.toString(oid) + "; The following are registered: " + Arrays.toString(names));
        }
        return (Curve) curvesByOid.get(Arrays.hashCode(oid));
    }

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

    public static final Curve prime256v1 = new Curve(
        new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
        new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
        new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
        new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
        "prime256v1",
        new long[]{1, 2, 840, 10045, 3, 1, 7}
    );

    public static final Curve p256 = prime256v1;

    static {
        add(secp256k1);
        add(prime256v1);
    }
}
