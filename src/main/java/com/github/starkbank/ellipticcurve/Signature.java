package com.github.starkbank.ellipticcurve;

import java.io.IOException;
import java.math.BigInteger;

import static com.github.starkbank.ellipticcurve.BinAscii.hexlify;
import static com.github.starkbank.ellipticcurve.Der.*;

/**
 * Created on 05-Jan-19
 *
 * @author Taron Petrosyan
 */
public class Signature {
    public BigInteger r;

    public BigInteger s;

    public Signature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public String toDer() {
        return encodeSequence(encodeInteger(r.longValue()), encodeInteger(s.longValue()));
    }

    public String toBase64() {
        return Base64.encodeBytes(toDer().getBytes());
    }

    public static Signature fromDer(String string) {
        String[] str = removeSequence(string);
        String rs = str[0];
        String empty = str[1];
        if (!empty.equals("")) {
            throw new RuntimeException(String.format("trailing junk after DER sig: %s", hexlify(empty)));
        }
        Object[] o = removeInteger(rs);
        long r = Long.valueOf(o[0].toString());
        String rest = (String) o[1];
        o = removeInteger(rest);
        long s = Long.valueOf(o[0].toString());
        empty = (String) o[1];
        if (!empty.equals("")) {
            throw new RuntimeException(String.format("trailing junk after DER numbers: %s", hexlify(empty)));
        }
        return new Signature(BigInteger.valueOf(r), BigInteger.valueOf(s));
    }

    public static Signature fromBase64(String string) {
        String der = null;
        try {
            der = new String(Base64.decode(string.getBytes()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Corrupted base64 string! Could not decode base64 from it");
        }
        return fromDer(der);
    }
}
