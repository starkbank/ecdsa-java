package com.starkbank.ellipticcurve;
import java.math.BigInteger;
import java.util.*;


/**
 * Elliptic Curve Equation.
 * y^2 = x^3 + A*x + B (mod P)
 */
public class Curve {

    /**
     * GLV endomorphism parameters for curves that support one (e.g. secp256k1).
     * phi((x, y)) = (beta * x mod P, y) corresponds to lambda * P. Basis vectors
     * (a1, b1), (a2, b2) from Gauss reduction used to split a 256-bit scalar k
     * into two ~128-bit scalars (k1, k2) with k = k1 + k2*lambda (mod N).
     */
    public static final class GLVParams {
        public final BigInteger beta;
        public final BigInteger lambda;
        public final BigInteger a1;
        public final BigInteger b1;
        public final BigInteger a2;
        public final BigInteger b2;

        public GLVParams(BigInteger beta, BigInteger lambda,
                         BigInteger a1, BigInteger b1,
                         BigInteger a2, BigInteger b2) {
            this.beta = beta;
            this.lambda = lambda;
            this.a1 = a1;
            this.b1 = b1;
            this.a2 = a2;
            this.b2 = b2;
        }
    }

    public BigInteger A;
    public BigInteger B;
    public BigInteger P;
    public BigInteger N;
    public int nBitLength;
    public Point G;
    public String name;
    public String nistName;
    public long[] oid;
    // null means no endomorphism; fall back to Shamir + JSF.
    public GLVParams glvParams;

    // Precomputed window table for fixed-base generator multiplication.
    // Lazily populated by Math.generatorTable and published via a volatile
    // store; safe to read without locks (Points are effectively immutable).
    volatile Point[] generatorTable;

    /**
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
        this(A, B, P, N, Gx, Gy, name, oid, null);
    }

    /**
     * @param A A
     * @param B B
     * @param P P
     * @param N N
     * @param Gx Gx
     * @param Gy Gy
     * @param name name
     * @param oid oid
     * @param nistName nistName
     */
    public Curve(BigInteger A, BigInteger B, BigInteger P, BigInteger N, BigInteger Gx, BigInteger Gy, String name, long[] oid, String nistName) {
        this(A, B, P, N, Gx, Gy, name, oid, nistName, null);
    }

    /**
     * @param A A
     * @param B B
     * @param P P
     * @param N N
     * @param Gx Gx
     * @param Gy Gy
     * @param name name
     * @param oid oid
     * @param nistName nistName
     * @param glvParams GLV endomorphism parameters, or null
     */
    public Curve(BigInteger A, BigInteger B, BigInteger P, BigInteger N, BigInteger Gx, BigInteger Gy, String name, long[] oid, String nistName, GLVParams glvParams) {
        this.A = A;
        this.B = B;
        this.P = P;
        this.N = N;
        this.nBitLength = N.bitLength();
        this.G = new Point(Gx, Gy);
        this.name = name;
        this.nistName = nistName;
        this.oid = oid;
        this.glvParams = glvParams;
    }

    /**
     * Verify if the point `p` is on the curve
     *
     * @param p Point p = Point(x, y)
     * @return true if point is on the curve otherwise false
     */
    public boolean contains(Point p) {
        if (p.x.compareTo(BigInteger.ZERO) < 0 || p.x.compareTo(this.P.subtract(BigInteger.ONE)) > 0) {
            return false;
        }
        if (p.y.compareTo(BigInteger.ZERO) < 0 || p.y.compareTo(this.P.subtract(BigInteger.ONE)) > 0) {
            return false;
        }
        // y^2 - (x^3 + A*x + B) mod P == 0
        BigInteger lhs = p.y.modPow(BigInteger.valueOf(2), this.P);
        BigInteger rhs = p.x.modPow(BigInteger.valueOf(3), this.P)
                .add(this.A.multiply(p.x))
                .add(this.B)
                .mod(this.P);
        return lhs.equals(rhs);
    }

    /**
     * @return int
     */
    public int length() {
        return (1 + N.toString(16).length()) / 2;
    }

    /**
     * Compute the y coordinate for a given x on the curve
     *
     * @param x the x coordinate
     * @param isEven whether the y coordinate should be even
     * @return the y coordinate
     */
    public BigInteger y(BigInteger x, boolean isEven) {
        BigInteger ySquared = x.modPow(BigInteger.valueOf(3), this.P)
                .add(this.A.multiply(x))
                .add(this.B)
                .mod(this.P);
        BigInteger y = Math.modularSquareRoot(ySquared, this.P);
        if (isEven != y.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            y = this.P.subtract(y);
        }
        return y;
    }

    public static final Curve secp256k1 = new Curve(
        BigInteger.ZERO,
        BigInteger.valueOf(7),
        new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
        new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
        new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
        new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
        "secp256k1",
        new long[]{1, 3, 132, 0, 10},
        null,
        // GLV endomorphism phi((x, y)) = (beta * x, y), equivalent to lambda * P.
        // Basis vectors from Gauss reduction; used to split a 256-bit scalar k
        // into two ~128-bit scalars (k1, k2) with k = k1 + k2 * lambda (mod N).
        new GLVParams(
            new BigInteger("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", 16),
            new BigInteger("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", 16),
            new BigInteger("3086d221a7d46bcde86c90e49284eb15", 16),
            new BigInteger("-e4437ed6010e88286f547fa90abfe4c3", 16),
            new BigInteger("114ca50f7a8e2f3f657c1108d9d44cfd8", 16),
            new BigInteger("3086d221a7d46bcde86c90e49284eb15", 16)
        )
    );

    public static final Curve prime256v1 = new Curve(
        new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
        new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
        new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
        new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
        "prime256v1",
        new long[]{1, 2, 840, 10045, 3, 1, 7},
        "P-256"
    );

    public static final Curve p256 = prime256v1;

    public static final List<Curve> supportedCurves = new ArrayList<>();

    public static final Map<Integer, Curve> curvesByOid = new HashMap<>();

    static {
        add(secp256k1);
        add(prime256v1);
    }

    /**
     * Register a curve so it can be looked up by OID
     *
     * @param curve the curve to register
     */
    public static void add(Curve curve) {
        supportedCurves.add(curve);
        curvesByOid.put(Arrays.hashCode(curve.oid), curve);
    }

    /**
     * Look up a curve by OID
     *
     * @param oid the OID to look up
     * @return the curve
     */
    public static Curve getByOid(long[] oid) {
        Curve curve = curvesByOid.get(Arrays.hashCode(oid));
        if (curve == null) {
            StringBuilder names = new StringBuilder();
            for (int i = 0; i < supportedCurves.size(); i++) {
                if (i > 0) names.append(", ");
                names.append(supportedCurves.get(i).name);
            }
            throw new RuntimeException(String.format(
                "Unknown curve with oid %s; The following are registered: %s",
                Arrays.toString(oid), names.toString()
            ));
        }
        return curve;
    }
}
