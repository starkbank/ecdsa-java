package com.github.starkbank.ellipticcurve;

import java.math.BigInteger;
import java.util.Arrays;

import static com.github.starkbank.ellipticcurve.BinAscii.hexlify;
import static com.github.starkbank.ellipticcurve.Curve.supportedCurves;
import static com.github.starkbank.ellipticcurve.Der.*;
import static com.github.starkbank.ellipticcurve.Math.numberFrom;
import static com.github.starkbank.ellipticcurve.Math.stringFrom;

/**
 * Created on 05-Jan-19
 *
 * @author Taron Petrosyan
 */
public class PublicKey {

    public BigInteger x;

    public BigInteger y;

    public Curve curve;

    public PublicKey(BigInteger x, BigInteger y, Curve curve) {
        this.x = x;
        this.y = y;
        this.curve = curve;
    }

    @Override
    public String toString() {
        return toString(false);
    }

    public String toString(boolean encoded) {
        String Xstr = stringFrom(x, curve.length());
        String Ystr = stringFrom(y, curve.length());
        return encoded ? (char) 0x00 + (char) 0x04 + Xstr + Ystr : Xstr + Ystr;
    }

    public String toDer() {
        long[] oidEcPublicKey = new long[]{1, 2, 840, 10045, 2, 1};
        String encodeEcAndOid = encodeSequence(encodeOid(oidEcPublicKey), encodeOid(curve.oid));
        return encodeSequence(encodeEcAndOid, encodeBitString(toString(true)));
    }

    public String toPem() {
        return Der.toPem(this.toDer(), "PUBLIC KEY");
    }

    public static PublicKey fromPem(String string) {
        return PublicKey.fromDer(Der.fromPem(string));
    }

    public static PublicKey fromDer(String string) {
        String[] str = removeSequence(string);
        String s1 = str[0];
        String empty = str[1];
        if (!"".equals(empty)) {
            throw new RuntimeException (String.format("trailing junk after DER pubkey: %s", hexlify(empty)));
        }
        str = removeSequence(s1);
        String s2 = str[0];
        String pointStrBitstring = str[1];
        Object[] o = removeObject(s2);
        String rest = (String) o[1];
        o = removeObject(rest);
        long[] oidCurve = (long[]) o[0];
        empty = (String) o[1];
        if (!"".equals(empty)) {
            throw new RuntimeException (String.format("trailing junk after DER pubkey objects: %s", hexlify(empty)));
        }
        Curve curve = (Curve) Curve.curvesByOid.get(oidCurve);
        if (curve == null) {
            throw new RuntimeException(String.format("Unknown curve with oid %s. I only know about these: %s",
                    Arrays.toString(oidCurve), Arrays.toString(supportedCurves.toArray())));

        }

        str = removeBitString(pointStrBitstring);
        String pointStr = str[0];
        empty = str[1];
        if (!"".equals(empty)) {
            throw new RuntimeException (String.format("trailing junk after pubkey pointstring: %s", hexlify(empty)));
        }
        return fromString(pointStr.substring(2),curve);

    }

    public static PublicKey fromString(String string, Curve curve, boolean validatePoint) {
        int baselen = curve.length();

        String xs = string.substring(0, baselen);
        String ys = string.substring(baselen);

        BigInteger x = numberFrom(xs);
        BigInteger y = numberFrom(ys);


        if (validatePoint && !curve.contains(x, y)) {
            throw new  RuntimeException(String.format("point (%s,%s) is not valid", x, y));
        }

        return new PublicKey(x, y, curve);

    }

    public static PublicKey fromString(String string, Curve curve) {
        return fromString(string, curve, true);
    }

    public static PublicKey fromString(String string, boolean validatePoint) {
//        Curve curve = new Curve();
        return fromString(string, null, validatePoint);
    }

    public static PublicKey fromString(String string) {
        return fromString(string, true);
    }
}
