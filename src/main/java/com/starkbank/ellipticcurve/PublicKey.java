package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.utils.Der;
import com.starkbank.ellipticcurve.utils.BinaryAscii;
import java.math.BigInteger;
import java.util.Arrays;
import static com.starkbank.ellipticcurve.Curve.secp256k1;


public class PublicKey {

    public Point point;
    public Curve curve;

    private static final String EVEN_TAG = "02";
    private static final String ODD_TAG = "03";
    private static final long[] ECDSA_PUBLIC_KEY_OID = new long[]{1, 2, 840, 10045, 2, 1};

    /**
     * @param point point
     * @param curve curve
     */
    public PublicKey(Point point, Curve curve) {
        this.point = point;
        this.curve = curve;
    }

    /**
     * @return ByteString
     */
    public ByteString toByteString() {
        return toByteString(false);
    }

    /**
     * @param encoded encoded
     * @return ByteString
     */
    public ByteString toByteString(boolean encoded) {
        ByteString xStr = BinaryAscii.stringFromNumber(point.x, curve.length());
        ByteString yStr = BinaryAscii.stringFromNumber(point.y, curve.length());
        xStr.insert(yStr.getBytes());
        if (encoded) {
            xStr.insert(0, new byte[]{0, 4});
        }
        return xStr;
    }

    /**
     * Get the hex string representation of the public key point
     *
     * @param encoded whether to include the 0004 prefix
     * @return hex string
     */
    public String toString(boolean encoded) {
        int baseLength = 2 * curve.length();
        String xHex = leftPad(point.x.toString(16), baseLength);
        String yHex = leftPad(point.y.toString(16), baseLength);
        String string = xHex + yHex;
        if (encoded) {
            return "0004" + string;
        }
        return string;
    }

    /**
     * Get the compressed hex string representation of the public key
     *
     * @return compressed hex string
     */
    public String toCompressed() {
        int baseLength = 2 * curve.length();
        String parityTag = point.y.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO) ? EVEN_TAG : ODD_TAG;
        String xHex = leftPad(point.x.toString(16), baseLength);
        return parityTag + xHex;
    }

    /**
     * @return ByteString
     */
    public ByteString toDer() {
        ByteString encodeEcAndOid = Der.encodeSequence(Der.encodeOid(ECDSA_PUBLIC_KEY_OID), Der.encodeOid(curve.oid));
        return Der.encodeSequence(encodeEcAndOid, Der.encodeBitString(this.toByteString(true)));
    }

    /**
     * @return String
     */
    public String toPem() {
        return Der.toPem(this.toDer(), "PUBLIC KEY");
    }

    /**
     * @param string string
     * @return PublicKey
     */
    public static PublicKey fromPem(String string) {
        return PublicKey.fromDer(Der.fromPem(string));
    }

    /**
     * @param string byteString
     * @return PublicKey
     */
    public static PublicKey fromDer(ByteString string) {
        ByteString[] str = Der.removeSequence(string);
        ByteString s1 = str[0];
        ByteString empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER pubkey: %s", BinaryAscii.hexFromBinary(empty)));
        }
        str = Der.removeSequence(s1);
        ByteString s2 = str[0];
        ByteString pointStrBitstring = str[1];
        Object[] o = Der.removeObject(s2);
        long[] publicKeyOid = (long[]) o[0];
        ByteString rest = (ByteString) o[1];
        o = Der.removeObject(rest);
        long[] oidCurve = (long[]) o[0];
        empty = (ByteString) o[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER pubkey objects: %s", BinaryAscii.hexFromBinary(empty)));
        }

        if (!Arrays.equals(publicKeyOid, ECDSA_PUBLIC_KEY_OID)) {
            throw new RuntimeException(String.format(
                "The Public Key Object Identifier (OID) should be %s, but %s was found instead",
                Arrays.toString(ECDSA_PUBLIC_KEY_OID), Arrays.toString(publicKeyOid)
            ));
        }

        Curve curve = Curve.getByOid(oidCurve);

        str = Der.removeBitString(pointStrBitstring);
        ByteString pointStr = str[0];
        empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after pubkey pointstring: %s", BinaryAscii.hexFromBinary(empty)));
        }
        return PublicKey.fromString(pointStr.substring(2), curve);
    }

    /**
     * @param string byteString
     * @param curve curve
     * @param validatePoint validatePoint
     * @return PublicKey
     */
    public static PublicKey fromString(ByteString string, Curve curve, boolean validatePoint) {
        int baselen = curve.length();

        ByteString xs = string.substring(0, baselen);
        ByteString ys = string.substring(baselen);

        Point p = new Point(BinaryAscii.numberFromString(xs.getBytes()), BinaryAscii.numberFromString(ys.getBytes()));

        PublicKey publicKey = new PublicKey(p, curve);
        if (!validatePoint) {
            return publicKey;
        }
        if (p.isAtInfinity()) {
            throw new RuntimeException("Public Key point is at infinity");
        }
        if (!curve.contains(p)) {
            throw new RuntimeException(String.format("Point (%s,%s) is not valid for curve %s", p.x, p.y, curve.name));
        }
        if (!Math.multiply(p, curve.N, curve.N, curve.A, curve.P).isAtInfinity()) {
            throw new RuntimeException(String.format("Point (%s,%s) * %s.N is not at infinity", p.x, p.y, curve.name));
        }
        return publicKey;
    }

    /**
     * @param string byteString
     * @param curve curve
     * @return PublicKey
     */
    public static PublicKey fromString(ByteString string, Curve curve) {
        return fromString(string, curve, true);
    }

    /**
     * @param string byteString
     * @param validatePoint validatePoint
     * @return PublicKey
     */
    public static PublicKey fromString(ByteString string, boolean validatePoint) {
        return fromString(string, secp256k1, validatePoint);
    }

    /**
     * @param string byteString
     * @return PublicKey
     */
    public static PublicKey fromString(ByteString string) {
        return fromString(string, true);
    }

    /**
     * Create a PublicKey from a hex string representation
     *
     * @param hexString hex string of x+y coordinates, optionally with 0004 prefix
     * @param curve the curve
     * @param validatePoint whether to validate the point
     * @return PublicKey
     */
    public static PublicKey fromString(String hexString, Curve curve, boolean validatePoint) {
        int baseLength = 2 * curve.length();
        if (hexString.length() > 2 * baseLength && hexString.startsWith("0004")) {
            hexString = hexString.substring(4);
        }
        String xs = hexString.substring(0, baseLength);
        String ys = hexString.substring(baseLength);
        Point p = new Point(new BigInteger(xs, 16), new BigInteger(ys, 16));
        PublicKey publicKey = new PublicKey(p, curve);
        if (!validatePoint) {
            return publicKey;
        }
        if (p.isAtInfinity()) {
            throw new RuntimeException("Public Key point is at infinity");
        }
        if (!curve.contains(p)) {
            throw new RuntimeException(String.format("Point (%s,%s) is not valid for curve %s", p.x, p.y, curve.name));
        }
        if (!Math.multiply(p, curve.N, curve.N, curve.A, curve.P).isAtInfinity()) {
            throw new RuntimeException(String.format("Point (%s,%s) * %s.N is not at infinity", p.x, p.y, curve.name));
        }
        return publicKey;
    }

    /**
     * Create a PublicKey from a hex string representation using default curve
     *
     * @param hexString hex string
     * @param curve the curve
     * @return PublicKey
     */
    public static PublicKey fromString(String hexString, Curve curve) {
        return fromString(hexString, curve, true);
    }

    /**
     * Create a PublicKey from a compressed hex string
     *
     * @param compressedHex the compressed public key hex (02/03 prefix + x coordinate)
     * @param curve the curve
     * @return PublicKey
     */
    public static PublicKey fromCompressed(String compressedHex, Curve curve) {
        String parityTag = compressedHex.substring(0, 2);
        String xHex = compressedHex.substring(2);
        if (!parityTag.equals(EVEN_TAG) && !parityTag.equals(ODD_TAG)) {
            throw new RuntimeException("Compressed string should start with 02 or 03");
        }
        BigInteger x = new BigInteger(xHex, 16);
        BigInteger y = curve.y(x, parityTag.equals(EVEN_TAG));
        return new PublicKey(new Point(x, y), curve);
    }

    /**
     * Create a PublicKey from a compressed hex string using secp256k1
     *
     * @param compressedHex the compressed public key hex
     * @return PublicKey
     */
    public static PublicKey fromCompressed(String compressedHex) {
        return fromCompressed(compressedHex, secp256k1);
    }

    private static String leftPad(String s, int length) {
        while (s.length() < length) {
            s = "0" + s;
        }
        return s;
    }
}
