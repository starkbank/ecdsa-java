package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.utils.Der;
import com.starkbank.ellipticcurve.utils.BinaryAscii;
import java.math.BigInteger;
import java.util.Arrays;
import static com.starkbank.ellipticcurve.Curve.secp256k1;
import static com.starkbank.ellipticcurve.Curve.supportedCurves;
import static com.starkbank.ellipticcurve.utils.BinaryAscii.numberFromString;
import static com.starkbank.ellipticcurve.utils.BinaryAscii.stringFromNumber;


public class PublicKey {

    public BigInteger x;
    public BigInteger y;
    public Curve curve;

    public PublicKey(BigInteger x, BigInteger y, Curve curve) {
        this.x = x;
        this.y = y;
        this.curve = curve;
    }

    public ByteString toByteString() {
        return toByteString(false);
    }

    public ByteString toByteString(boolean encoded) {
        ByteString xStr = stringFromNumber(x, curve.length());
        ByteString yStr = stringFromNumber(y, curve.length());
        xStr.insert(yStr.getBytes());
        if(encoded) {
            xStr.insert(0, new byte[]{0, 4} );
        }
        return xStr;
    }

    public ByteString toDer() {
        long[] oidEcPublicKey = new long[]{1, 2, 840, 10045, 2, 1};
        ByteString encodeEcAndOid = Der.encodeSequence(Der.encodeOid(oidEcPublicKey), Der.encodeOid(curve.oid.getOid()));
        return Der.encodeSequence(encodeEcAndOid, Der.encodeBitString(this.toByteString(true)));
    }

    public String toPem() {
        return Der.toPem(this.toDer(), "PUBLIC KEY");
    }

    public static PublicKey fromPem(String string) {
        return PublicKey.fromDer(Der.fromPem(string));
    }

    public static PublicKey fromDer(ByteString string) {
        ByteString[] str = Der.removeSequence(string);
        ByteString s1 = str[0];
        ByteString empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException (String.format("trailing junk after DER pubkey: %s", BinaryAscii.hexFromBinary(empty)));
        }
        str = Der.removeSequence(s1);
        ByteString s2 = str[0];
        ByteString pointStrBitstring = str[1];
        Object[] o = Der.removeObject(s2);
        ByteString rest = (ByteString) o[1];
        o = Der.removeObject(rest);
        long[] oidCurve = (long[]) o[0];
        empty = (ByteString) o[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException (String.format("trailing junk after DER pubkey objects: %s", BinaryAscii.hexFromBinary(empty)));
        }

        Curve curve = (Curve) Curve.curvesByOid.get(new Curve.OID(oidCurve));
        if (curve == null) {
            throw new RuntimeException(String.format("Unknown curve with oid %s. I only know about these: %s", Arrays.toString(oidCurve), Arrays.toString(supportedCurves.toArray())));
        }

        str = Der.removeBitString(pointStrBitstring);
        ByteString pointStr = str[0];
        empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException (String.format("trailing junk after pubkey pointstring: %s", BinaryAscii.hexFromBinary(empty)));
        }
        return PublicKey.fromString(pointStr.substring(2), curve);
    }

    public static PublicKey fromString(ByteString string, Curve curve, boolean validatePoint) {
        int baselen = curve.length();

        ByteString xs = string.substring(0, baselen);
        ByteString ys = string.substring(baselen);

        BigInteger x = numberFromString(xs.getBytes());
        BigInteger y = numberFromString(ys.getBytes());


        if (validatePoint && !curve.contains(x, y)) {
            throw new  RuntimeException(String.format("point (%s,%s) is not valid", x, y));
        }

        return new PublicKey(x, y, curve);
    }

    public static PublicKey fromString(ByteString string, Curve curve) {
        return fromString(string, curve, true);
    }

    public static PublicKey fromString(ByteString string, boolean validatePoint) {
        return fromString(string, secp256k1, validatePoint);
    }

    public static PublicKey fromString(ByteString string) {
        return fromString(string, true);
    }
}
