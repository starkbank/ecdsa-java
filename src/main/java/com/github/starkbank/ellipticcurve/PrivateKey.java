package com.github.starkbank.ellipticcurve;

import com.github.starkbank.ellipticcurve.utils.Der;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static com.github.starkbank.ellipticcurve.utils.BinAscii.hexlify;
import static com.github.starkbank.ellipticcurve.Curve.supportedCurves;
import static com.github.starkbank.ellipticcurve.utils.Der.*;
import static com.github.starkbank.ellipticcurve.Math.*;

/**
 * Created on 05-Jan-19
 *
 * @author Taron Petrosyan
 */
public class PrivateKey {
    public Curve curve;

    public BigInteger secret;

    public PrivateKey() {
        this(Curve.secp256k1, null);
        Random random = new SecureRandom();
        secret = new BigInteger(curve.n.toByteArray().length * 8 - 1, random);
    }

    public PrivateKey(Curve curve, BigInteger secret) {
        this.curve = curve;
        this.secret = secret;
    }

    public PublicKey publicKey() {
        Curve curve = this.curve;
        Point publicKey = multiply(new Point(curve.gX, curve.gY), this.secret, curve.n, curve.a, curve.p);
        return new PublicKey(publicKey.x, publicKey.y, curve);
    }

    public ByteString toByteString() {
        return stringFrom(this.secret, this.curve.length());
    }

    public ByteString toDer() {
        ByteString encodedPublicKey = this.publicKey().toByteString(true);
        return encodeSequence(
                encodeInteger(BigInteger.valueOf(1)),
                encodeOctetString(this.toByteString()),
                encodeConstructed(0, encodeOid(this.curve.oid.getOid())),
                encodeConstructed(1, encodeBitString(encodedPublicKey)));
    }

    public String toPem() {
        return Der.toPem(this.toDer(), "EC PRIVATE KEY");
    }


    public static PrivateKey fromPem(String string) {
        String privkeyPem = string.substring(string.indexOf("-----BEGIN EC PRIVATE KEY-----"));
        return PrivateKey.fromDer(Der.fromPem(privkeyPem));
    }

    public static PrivateKey fromDer(String string) {
        return fromDer(new ByteString(string.getBytes()));
    }

    public static PrivateKey fromDer(ByteString string) {
        ByteString[] str = removeSequence(string);
        ByteString s = str[0];
        ByteString empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER privkey: %s", hexlify(empty)));
        }

        Object[] o = removeInteger(s);
        long one = Long.valueOf(o[0].toString());
        s = (ByteString) o[1];
        if (one != 1) {
            throw new RuntimeException(String.format("expected '1' at start of DER privkey, got %d", one));
        }

        str = removeOctetString(s);
        ByteString privkeyStr = str[0];
        s = str[1];
        Object[] t = removeConstructed(s);
        long tag = Long.valueOf(t[0].toString());
        ByteString curveOidStr = (ByteString) t[1];
        s = (ByteString) t[2];
        if (tag != 0) {
            throw new RuntimeException(String.format("expected tag 0 in DER privkey, got %d", tag));
        }

        o = removeObject(curveOidStr);
        long[] oidCurve = (long[]) o[0];
        empty = (ByteString) o[1];
        if (!"".equals(empty.toString())) {
            throw new RuntimeException(String.format("trailing junk after DER privkey curve_oid: %s", hexlify(empty)));
        }

        Curve curve = (Curve) Curve.curvesByOid.get(new Curve.OID(oidCurve));
        if (curve == null) {
            throw new RuntimeException(String.format("Unknown curve with oid %s. I only know about these: %s",
                    Arrays.toString(oidCurve), Arrays.toString(supportedCurves.toArray())));

        }


        if (privkeyStr.length() < curve.length()) {
            int l = curve.length() - privkeyStr.length();
            byte[] bytes = new byte[l + privkeyStr.length()];
            for (int i = 0; i < curve.length() - privkeyStr.length(); i++) {
                bytes[i] = 0;
            }
            byte[] privateKey = privkeyStr.getBytes();
            System.arraycopy(privateKey, 0, bytes, l, bytes.length - l);
            privkeyStr = new ByteString(bytes);
        }

        return PrivateKey.fromString(privkeyStr, curve);
    }

    public static PrivateKey fromString(ByteString string, Curve curve) {
        return new PrivateKey(curve, numberFrom(string.getBytes()));
    }

    public static PrivateKey fromString(String string) {
        return fromString(new ByteString(string.getBytes()));
    }

    public static PrivateKey fromString(ByteString string) {
        return PrivateKey.fromString(string, Curve.secp256k1);
    }
}
