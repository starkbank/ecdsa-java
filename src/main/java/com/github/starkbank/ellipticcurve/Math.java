package com.github.starkbank.ellipticcurve;

import java.math.BigInteger;

/**
 * Created on 05-Jan-19
 *
 * @author Taron Petrosyan
 */
public final class Math {

    private Math() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Fast way to multiply point and scalar in elliptic curves
     *
     * @param a First Point to multiply
     * @param n Scalar to multiply
     * @param N Order of the elliptic curve
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
     * @return Point that represents the sum of First and Second Point
     */
    public static Point multiply(Point a, BigInteger n, BigInteger N, BigInteger P, BigInteger A) {
        return fromJacobian(jacobianMultiply(toJacobian(a), n, N, A, P), P);
    }

    /**
     * Fast way to add two points in elliptic curves
     *
     * @param a First Point you want to add
     * @param b Second Point you want to add
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
     * @return Point that represents the sum of First and Second Point
     */
    public static Point add(Point a, Point b, BigInteger A, BigInteger P) {
        return fromJacobian(jacobianAdd(toJacobian(a), toJacobian(b), A, P), P);
    }

    /**
     * Extended Euclidean Algorithm. It's the 'division' in elliptic curves
     *
     * @param a Divisor
     * @param n Mod for division
     * @return Value representing the division
     */
    public static BigInteger inv(BigInteger a, BigInteger n) {
        if (a.compareTo(BigInteger.ZERO) == 0) {
            return BigInteger.ZERO;
        }
        BigInteger lm = BigInteger.ONE;
        BigInteger hm = BigInteger.ZERO;
        BigInteger high = n;
        BigInteger low = a.remainder(n);
        BigInteger r, nm, nw;
        while (low.compareTo(BigInteger.ONE) > 0) {
            r = high.divide(low);
            nm = hm.subtract(lm.multiply(r));
            nw = high.subtract(low.multiply(r));
            high = low;
            hm = lm;
            low = nw;
            lm = nm;
        }
        return lm.remainder(n);
    }

    /**
     * Convert point to Jacobian coordinates
     *
     * @param p the point you want to transform
     * @return Point in Jacobian coordinates
     */
    public static Point toJacobian(Point p) {
        return new Point(p.x, p.y, BigInteger.ONE);
    }

    /**
     * Convert point back from Jacobian coordinates
     *
     * @param p the point you want to transform
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
     * @return Point in default coordinates
     */
    public static Point fromJacobian(Point p, BigInteger P) {
        BigInteger z = inv(p.z, P);
        BigInteger x = p.x.multiply(z.pow(2).remainder(P));
        BigInteger y = p.y.multiply(z.pow(3).remainder(P));
        return new Point(x, y, BigInteger.ZERO);
    }

    /**
     * Double a point in elliptic curves
     *
     * @param p the point you want to transform
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
     * @return the result point doubled in elliptic curves
     */
    public static Point jacobianDouble(Point p, BigInteger A, BigInteger P) {
        if (p.y == null || p.y.equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);
        }
        BigInteger ysq = p.y.pow(2).remainder(P);
        BigInteger S = BigInteger.valueOf(4).multiply(p.x).multiply(ysq).remainder(P);
        BigInteger M = BigInteger.valueOf(3).multiply(p.x.pow(2)).add(A.multiply(p.z.pow(4))).remainder(P);
        BigInteger nx = M.pow(2).subtract(BigInteger.TWO.multiply(S)).remainder(P);
        BigInteger ny = M.multiply(S.subtract(nx)).subtract(BigInteger.valueOf(8).multiply(ysq.pow(2))).remainder(P);
        BigInteger nz = BigInteger.TWO.multiply(p.y).multiply(p.z).remainder(P);
        return new Point(nx, ny, nz);
    }

    /**
     * Add two points in elliptic curves
     *
     * @param p First Point you want to add
     * @param q Second Point you want to add
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
     * @return Point that represents the sum of First and Second Point
     */
    public static Point jacobianAdd(Point p, Point q, BigInteger A, BigInteger P) {
        if (p.y == null || p.y.equals(BigInteger.ZERO)) {
            return q;
        }
        if (q.y == null || q.y.equals(BigInteger.ZERO)) {
            return p;
        }
        BigInteger U1 = p.x.multiply(q.z.pow(2)).remainder(P);
        BigInteger U2 = q.x.multiply(p.z.pow(2)).remainder(P);
        BigInteger S1 = p.y.multiply(q.z.pow(3)).remainder(P);
        BigInteger S2 = q.y.multiply(p.z.pow(3)).remainder(P);
        if (U1.equals(U2)) {
            if (!S1.equals(S2)) {
                return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
            }
            return jacobianDouble(p, A, P);
        }
        BigInteger H = U2.subtract(U1);
        BigInteger R = S2.subtract(S1);
        BigInteger H2 = H.multiply(H).remainder(P);
        BigInteger H3 = H.multiply(H2).remainder(P);
        BigInteger U1H2 = U1.multiply(H2).remainder(P);
        BigInteger nx = R.pow(2).subtract(H3).subtract(BigInteger.TWO.multiply(U1H2)).remainder(P);
        BigInteger ny = R.multiply(U1H2.subtract(nx)).subtract(S1.multiply(H3)).remainder(P);
        BigInteger nz = H.multiply(p.z).multiply(q.z).remainder(P);
        return new Point(nx, ny, nz);
    }

    /**
     * Multiply point and scalar in elliptic curves
     *
     * @param p First Point to multiply
     * @param n Scalar to multiply
     * @param N Order of the elliptic curve
     * @param A Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
     * @param P Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
     * @return Point that represents the product of First Point and scalar
     */
    public static Point jacobianMultiply(Point p, BigInteger n, BigInteger N, BigInteger A, BigInteger P) {
        if (BigInteger.ZERO.equals(p.y) || BigInteger.ZERO.equals(n)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
        }
        if (BigInteger.ONE.equals(n)) {
            return p;
        }
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(N) >= 0) {
            return jacobianMultiply(p, n.remainder(N), N, A, P);
        }
        if (n.remainder(BigInteger.TWO).equals(BigInteger.ZERO)) {
            return jacobianDouble(jacobianMultiply(p, n.divide(BigInteger.TWO), N, A, P), A, P);
        }
        if (n.remainder(BigInteger.TWO).equals(BigInteger.ONE)) {
            return jacobianAdd(jacobianDouble(jacobianMultiply(p, n.divide(BigInteger.TWO), N, A, P), A, P), p, A, P);
        }
        return null;
    }

    /**
     * Get a number representation of a string
     *
     * @param string String to be converted in a number
     * @return Number in hex from string
     */
    public static BigInteger numberFrom(String string) {
        byte[] bytes = string.getBytes();
        StringBuilder hexString = new StringBuilder();

        for (byte aByte : bytes) {
            String hex = Integer.toHexString(0xFF & aByte);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return new BigInteger(hexString.toString(), 16);
    }

    /**
     * Get a string representation of a number
     *
     * @param number number to be converted in a string
     * @param length length max number of character for the string
     * @return hexadecimal string
     */
    public static String stringFrom(BigInteger number, int length) {
        String fmtStr = "%0" + String.valueOf(2 * length) + "x";
        String hexString = String.format(fmtStr, number);

        byte[] bytes = new byte[hexString.length() * 2];

        for (int i = 0, j = 0; i < hexString.length(); i += 2, j++) {
            bytes[j] = Byte.valueOf(hexString.substring(i, i + 2), 16);
        }
        return new String(bytes);
    }
}
