package com.starkbank.ellipticcurve;
import java.math.BigInteger;


public final class Math {

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger EIGHT = BigInteger.valueOf(8);

    private static final int GENERATOR_WINDOW_BITS = 4;
    private static final int GENERATOR_WINDOW_SIZE = 1 << GENERATOR_WINDOW_BITS;
    private static final int GENERATOR_WINDOW_MASK = GENERATOR_WINDOW_SIZE - 1;

    /**
     * Tonelli-Shanks algorithm for modular square root. Works for all odd primes.
     *
     * @param value the value to compute the square root of
     * @param prime the prime modulus
     * @return the modular square root
     */
    public static BigInteger modularSquareRoot(BigInteger value, BigInteger prime) {
        if (value.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }
        if (prime.equals(TWO)) {
            return value.mod(TWO);
        }

        // Factor out powers of 2: prime - 1 = Q * 2^S
        BigInteger Q = prime.subtract(BigInteger.ONE);
        int S = 0;
        while (Q.mod(TWO).equals(BigInteger.ZERO)) {
            Q = Q.divide(TWO);
            S++;
        }

        if (S == 1) {
            // prime = 3 (mod 4) fast path
            return value.modPow(prime.add(BigInteger.ONE).divide(FOUR), prime);
        }

        // Find a quadratic non-residue z
        BigInteger z = TWO;
        BigInteger primeMinusOne = prime.subtract(BigInteger.ONE);
        BigInteger halfPrimeMinusOne = primeMinusOne.divide(TWO);
        while (!z.modPow(halfPrimeMinusOne, prime).equals(primeMinusOne)) {
            z = z.add(BigInteger.ONE);
        }

        int M = S;
        BigInteger c = z.modPow(Q, prime);
        BigInteger t = value.modPow(Q, prime);
        BigInteger R = value.modPow(Q.add(BigInteger.ONE).divide(TWO), prime);

        while (true) {
            if (t.equals(BigInteger.ONE)) {
                return R;
            }

            // Find the least i such that t^(2^i) = 1 (mod prime)
            int i = 1;
            BigInteger temp = t.multiply(t).mod(prime);
            while (!temp.equals(BigInteger.ONE)) {
                temp = temp.multiply(temp).mod(prime);
                i++;
            }

            BigInteger b = c.modPow(BigInteger.ONE.shiftLeft(M - i - 1), prime);
            M = i;
            c = b.multiply(b).mod(prime);
            t = t.multiply(c).mod(prime);
            R = R.multiply(b).mod(prime);
        }
    }

    /**
     * Fast way to multiply point and scalar in elliptic curves
     *
     * @param p First Point to multiply
     * @param n Scalar to multiply
     * @param N Order of the elliptic curve
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
     * @return Point that represents the scalar multiplication
     */
    public static Point multiply(Point p, BigInteger n, BigInteger N, BigInteger A, BigInteger P) {
        return fromJacobian(jacobianMultiply(toJacobian(p), n, N, A, P), P);
    }

    /**
     * Fast way to add two points in elliptic curves
     *
     * @param p First Point you want to add
     * @param q Second Point you want to add
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
     * @return Point that represents the sum of First and Second Point
     */
    public static Point add(Point p, Point q, BigInteger A, BigInteger P) {
        return fromJacobian(jacobianAdd(toJacobian(p), toJacobian(q), A, P), P);
    }

    /**
     * Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
     * Not constant-time -- use only with public scalars (e.g. verification).
     *
     * @param p1 First point
     * @param n1 First scalar
     * @param p2 Second point
     * @param n2 Second scalar
     * @param N Order of the elliptic curve
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
     * @return Point n1*p1 + n2*p2
     */
    public static Point multiplyAndAdd(Point p1, BigInteger n1, Point p2, BigInteger n2, BigInteger N, BigInteger A, BigInteger P) {
        return fromJacobian(
            shamirMultiply(toJacobian(p1), n1, toJacobian(p2), n2, N, A, P),
            P
        );
    }

    /**
     * Modular inverse via the extended Euclidean algorithm
     * (BigInteger.modInverse). Roughly 2-3x faster than Fermat's little
     * theorem for 256-bit operands.
     *
     * @param x Divisor (must be coprime to n)
     * @param n Mod for division
     * @return Value representing the modular inverse
     */
    public static BigInteger inv(BigInteger x, BigInteger n) {
        if (x.mod(n).equals(BigInteger.ZERO)) {
            throw new ArithmeticException("0 has no modular inverse");
        }
        return x.modInverse(n);
    }

    /**
     * Fast scalar multiplication n*G where G is the curve generator, using
     * a precomputed window table (2^w-ary method). Roughly 2-3x faster
     * than variable-base multiplication because doublings stay cheap and
     * additions use pre-stored multiples of G.
     *
     * @param curve Elliptic curve whose generator G is multiplied
     * @param n Scalar multiplier
     * @return Point n*G
     */
    public static Point multiplyGenerator(Curve curve, BigInteger n) {
        if (n.signum() < 0 || n.compareTo(curve.N) >= 0) {
            n = n.mod(curve.N);
        }
        if (n.equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);
        }

        Point[] table = generatorTable(curve);
        int w = GENERATOR_WINDOW_BITS;
        BigInteger A = curve.A;
        BigInteger P = curve.P;

        // Jacobian infinity (y=0 triggers early-return in jacobianAdd)
        Point r = new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
        int startBit = ((curve.nBitLength - 1) / w) * w;
        for (int bit = startBit; bit >= 0; bit -= w) {
            for (int j = 0; j < w; j++) {
                r = jacobianDouble(r, A, P);
            }
            int window = 0;
            for (int j = w - 1; j >= 0; j--) {
                window = (window << 1) | (n.testBit(bit + j) ? 1 : 0);
            }
            window &= GENERATOR_WINDOW_MASK;
            if (window != 0) {
                r = jacobianAdd(r, table[window], A, P);
            }
        }
        return fromJacobian(r, P);
    }

    /**
     * Lazily build and cache the precomputed window table
     * [infinity, G, 2G, ..., (2^w - 1) G] in Jacobian coordinates on the
     * given curve. Idempotent: repeated calls return the same array.
     *
     * @param curve Elliptic curve whose generator is tabulated
     * @return Window table of Jacobian points
     */
    static Point[] generatorTable(Curve curve) {
        Point[] cached = curve.generatorTable;
        if (cached != null) {
            return cached;
        }
        BigInteger A = curve.A;
        BigInteger P = curve.P;
        Point G = new Point(curve.G.x, curve.G.y, BigInteger.ONE);
        Point[] table = new Point[GENERATOR_WINDOW_SIZE];
        table[0] = new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
        table[1] = G;
        for (int i = 2; i < GENERATOR_WINDOW_SIZE; i++) {
            table[i] = jacobianAdd(table[i - 1], G, A, P);
        }
        curve.generatorTable = table;
        return table;
    }

    /**
     * Convert point to Jacobian coordinates
     *
     * @param p the point you want to transform
     * @return Point in Jacobian coordinates
     */
    static Point toJacobian(Point p) {
        return new Point(p.x, p.y, BigInteger.ONE);
    }

    /**
     * Convert point back from Jacobian coordinates
     *
     * @param p the point you want to transform
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
     * @return Point in default coordinates
     */
    static Point fromJacobian(Point p, BigInteger P) {
        if (p.y.equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);
        }
        BigInteger z = inv(p.z, P);
        BigInteger x = p.x.multiply(z.pow(2)).mod(P);
        BigInteger y = p.y.multiply(z.pow(3)).mod(P);
        return new Point(x, y, BigInteger.ZERO);
    }

    /**
     * Double a point in elliptic curves
     *
     * @param p the point you want to double
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
     * @return the result point doubled
     */
    static Point jacobianDouble(Point p, BigInteger A, BigInteger P) {
        if (p.y.equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);
        }
        BigInteger px = p.x, py = p.y, pz = p.z;
        BigInteger ysq = py.multiply(py).mod(P);
        BigInteger S = FOUR.multiply(px).multiply(ysq).mod(P);
        BigInteger pz2 = pz.multiply(pz).mod(P);
        BigInteger M;
        if (A.signum() == 0) {
            // A = 0 (secp256k1): skip A*pz^4 term
            M = THREE.multiply(px).multiply(px).mod(P);
        } else if (A.equals(P.subtract(THREE))) {
            // A = -3 (prime256v1): M = 3*(px - pz^2)*(px + pz^2)
            M = THREE.multiply(px.subtract(pz2)).multiply(px.add(pz2)).mod(P);
        } else {
            M = THREE.multiply(px).multiply(px).add(A.multiply(pz2).multiply(pz2)).mod(P);
        }
        BigInteger nx = M.multiply(M).subtract(TWO.multiply(S)).mod(P);
        BigInteger ny = M.multiply(S.subtract(nx)).subtract(EIGHT.multiply(ysq).multiply(ysq)).mod(P);
        BigInteger nz = TWO.multiply(py).multiply(pz).mod(P);
        return new Point(nx, ny, nz);
    }

    /**
     * Add two points in elliptic curves
     *
     * @param p First Point you want to add
     * @param q Second Point you want to add
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
     * @return Point that represents the sum of First and Second Point
     */
    static Point jacobianAdd(Point p, Point q, BigInteger A, BigInteger P) {
        if (p.y.equals(BigInteger.ZERO)) {
            return q;
        }
        if (q.y.equals(BigInteger.ZERO)) {
            return p;
        }
        BigInteger px = p.x, py = p.y, pz = p.z;
        BigInteger qx = q.x, qy = q.y, qz = q.z;

        BigInteger qz2 = qz.multiply(qz).mod(P);
        BigInteger pz2 = pz.multiply(pz).mod(P);
        BigInteger U1 = px.multiply(qz2).mod(P);
        BigInteger U2 = qx.multiply(pz2).mod(P);
        BigInteger S1 = py.multiply(qz2).multiply(qz).mod(P);
        BigInteger S2 = qy.multiply(pz2).multiply(pz).mod(P);

        if (U1.equals(U2)) {
            if (!S1.equals(S2)) {
                return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
            }
            return jacobianDouble(p, A, P);
        }

        BigInteger H = U2.subtract(U1);
        BigInteger R = S2.subtract(S1);
        BigInteger H2 = H.multiply(H).mod(P);
        BigInteger H3 = H.multiply(H2).mod(P);
        BigInteger U1H2 = U1.multiply(H2).mod(P);
        BigInteger nx = R.multiply(R).subtract(H3).subtract(TWO.multiply(U1H2)).mod(P);
        BigInteger ny = R.multiply(U1H2.subtract(nx)).subtract(S1.multiply(H3)).mod(P);
        BigInteger nz = H.multiply(pz).multiply(qz).mod(P);
        return new Point(nx, ny, nz);
    }

    /**
     * Multiply point and scalar in elliptic curves using Montgomery ladder
     * for constant-time execution.
     *
     * @param p First Point to multiply
     * @param n Scalar to multiply
     * @param N Order of the elliptic curve
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
     * @return Point that represents the scalar multiplication
     */
    static Point jacobianMultiply(Point p, BigInteger n, BigInteger N, BigInteger A, BigInteger P) {
        if (p.y.equals(BigInteger.ZERO) || n.equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
        }

        if (n.signum() < 0 || n.compareTo(N) >= 0) {
            n = n.mod(N);
        }

        if (n.equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
        }

        // Montgomery ladder: always performs one add and one double per bit
        Point r0 = new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
        Point r1 = new Point(p.x, p.y, p.z);

        for (int i = n.bitLength() - 1; i >= 0; i--) {
            if (!n.testBit(i)) {
                r1 = jacobianAdd(r0, r1, A, P);
                r0 = jacobianDouble(r0, A, P);
            } else {
                r0 = jacobianAdd(r0, r1, A, P);
                r1 = jacobianDouble(r1, A, P);
            }
        }

        return r0;
    }

    /**
     * Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
     * Not constant-time -- use only with public scalars (e.g. verification).
     *
     * @param jp1 First point in Jacobian coordinates
     * @param n1 First scalar
     * @param jp2 Second point in Jacobian coordinates
     * @param n2 Second scalar
     * @param N Order of the elliptic curve
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod P)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod P)
     * @return Point n1*p1 + n2*p2 in Jacobian coordinates
     */
    static Point shamirMultiply(Point jp1, BigInteger n1, Point jp2, BigInteger n2, BigInteger N, BigInteger A, BigInteger P) {
        if (n1.signum() < 0 || n1.compareTo(N) >= 0) {
            n1 = n1.mod(N);
        }
        if (n2.signum() < 0 || n2.compareTo(N) >= 0) {
            n2 = n2.mod(N);
        }

        Point jp1p2 = jacobianAdd(jp1, jp2, A, P);

        int l = java.lang.Math.max(n1.bitLength(), n2.bitLength());
        Point r = new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);

        for (int i = l - 1; i >= 0; i--) {
            r = jacobianDouble(r, A, P);
            boolean b1 = n1.testBit(i);
            boolean b2 = n2.testBit(i);
            if (b1) {
                r = jacobianAdd(r, b2 ? jp1p2 : jp1, A, P);
            } else if (b2) {
                r = jacobianAdd(r, jp2, A, P);
            }
        }

        return r;
    }
}
