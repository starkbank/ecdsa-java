package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.utils.Der;
import com.starkbank.ellipticcurve.utils.BinaryAscii;
import com.starkbank.ellipticcurve.utils.RandomInteger;
import java.math.BigInteger;


public class PrivateKey {

    public Curve curve;
    public BigInteger secret;

    /**
     * Generate a new random private key on secp256k1
     */
    public PrivateKey() {
        this(Curve.secp256k1, null);
    }

    /**
     * Create a private key on a specified curve. If secret is null, a random one is generated.
     *
     * @param curve curve
     * @param secret secret
     */
    public PrivateKey(Curve curve, BigInteger secret) {
        this.curve = curve;
        this.secret = secret != null ? secret : RandomInteger.between(BigInteger.ONE, curve.N.subtract(BigInteger.ONE));
    }

    /**
     * @return PublicKey
     */
    public PublicKey publicKey() {
        Curve curve = this.curve;
        Point publicPoint = Math.multiply(curve.G, this.secret, curve.N, curve.A, curve.P);
        return new PublicKey(publicPoint, curve);
    }

    /**
     * Get the hex string representation of the private key secret
     *
     * @return hex string
     */
    public String toString() {
        String hex = this.secret.toString(16);
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        return hex;
    }

    /**
     * @return ByteString
     */
    public ByteString toByteString() {
        return BinaryAscii.stringFromNumber(this.secret, this.curve.length());
    }

    /**
     * @return ByteString
     */
    public ByteString toDer() {
        ByteString encodedPublicKey = this.publicKey().toByteString(true);
        return Der.encodeSequence(
                Der.encodeInteger(BigInteger.valueOf(1)),
                Der.encodeOctetString(this.toByteString()),
                Der.encodeConstructed(0, Der.encodeOid(this.curve.oid)),
                Der.encodeConstructed(1, Der.encodeBitString(encodedPublicKey)));
    }

    /**
     * @return String
     */
    public String toPem() {
        return Der.toPem(this.toDer(), "EC PRIVATE KEY");
    }

    /**
     * @param string string
     * @return PrivateKey
     */
    public static PrivateKey fromPem(String string) {
        String privkeyPem = string.substring(string.indexOf("-----BEGIN EC PRIVATE KEY-----"));
        return PrivateKey.fromDer(Der.fromPem(privkeyPem));
    }

    /**
     * @param string string
     * @return PrivateKey
     */
    public static PrivateKey fromDer(String string) {
        return fromDer(new ByteString(string.getBytes()));
    }

    /**
     * @param string ByteString
     * @return PrivateKey
     */
    public static PrivateKey fromDer(ByteString string) {
        ByteString[] str = Der.removeSequence(string);
        ByteString s = str[0];
        ByteString empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER privkey: %s", BinaryAscii.hexFromBinary(empty)));
        }

        Object[] o = Der.removeInteger(s);
        long one = Long.valueOf(o[0].toString());
        s = (ByteString) o[1];
        if (one != 1) {
            throw new RuntimeException(String.format("expected '1' at start of DER privkey, got %d", one));
        }

        str = Der.removeOctetString(s);
        ByteString privkeyStr = str[0];
        s = str[1];
        Object[] t = Der.removeConstructed(s);
        long tag = Long.valueOf(t[0].toString());
        ByteString curveOidStr = (ByteString) t[1];
        s = (ByteString) t[2];
        if (tag != 0) {
            throw new RuntimeException(String.format("expected tag 0 in DER privkey, got %d", tag));
        }

        o = Der.removeObject(curveOidStr);
        long[] oidCurve = (long[]) o[0];
        empty = (ByteString) o[1];
        if (!"".equals(empty.toString())) {
            throw new RuntimeException(String.format("trailing junk after DER privkey curve_oid: %s", BinaryAscii.hexFromBinary(empty)));
        }
        Curve curve = Curve.getByOid(oidCurve);

        if (privkeyStr.length() < curve.length()) {
            int l = curve.length() - privkeyStr.length();
            byte[] bytes = new byte[l + privkeyStr.length()];
            byte[] privateKey = privkeyStr.getBytes();
            System.arraycopy(privateKey, 0, bytes, l, bytes.length - l);
            privkeyStr = new ByteString(bytes);
        }

        return PrivateKey.fromString(privkeyStr, curve);
    }

    /**
     * @param string byteString
     * @param curve curve
     * @return PrivateKey
     */
    public static PrivateKey fromString(ByteString string, Curve curve) {
        return new PrivateKey(curve, BinaryAscii.numberFromString(string.getBytes()));
    }

    /**
     * @param string string
     * @return PrivateKey
     */
    public static PrivateKey fromString(String string) {
        return fromString(new ByteString(string.getBytes()));
    }

    /**
     * @param string byteString
     * @return PrivateKey
     */
    public static PrivateKey fromString(ByteString string) {
        return PrivateKey.fromString(string, Curve.secp256k1);
    }

    /**
     * Create a PrivateKey from a hex string and curve
     *
     * @param hexString hex string representation of the secret
     * @param curve the curve
     * @return PrivateKey
     */
    public static PrivateKey fromString(String hexString, Curve curve) {
        return new PrivateKey(curve, new BigInteger(hexString, 16));
    }
}
