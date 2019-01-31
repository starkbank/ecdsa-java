package com.github.starkbank.ellipticcurve;

import com.github.starkbank.ellipticcurve.utils.Base64;

import java.io.IOException;
import java.math.BigInteger;

import static com.github.starkbank.ellipticcurve.utils.BinAscii.hexlify;
import static com.github.starkbank.ellipticcurve.utils.Der.*;

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

    public ByteString toDer() {
        return encodeSequence(encodeInteger(r), encodeInteger(s));
    }

    public String toBase64() {
        return Base64.encodeBytes(toDer().getBytes());
    }

    public static Signature fromDer(ByteString string) {
        ByteString[] str = removeSequence(string);
        ByteString rs = str[0];
        ByteString empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER sig: %s", hexlify(empty)));
        }
        Object[] o = removeInteger(rs);
        BigInteger r = new BigInteger(o[0].toString());
        ByteString rest = (ByteString) o[1];
        o = removeInteger(rest);
        BigInteger s = new BigInteger(o[0].toString());
        empty = (ByteString) o[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER numbers: %s", hexlify(empty)));
        }
        return new Signature(r, s);
    }

    public static Signature fromBase64(ByteString string) {
        ByteString der = null;
        try {
            der = new ByteString(Base64.decode(string.getBytes()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Corrupted base64 string! Could not decode base64 from it");
        }
        return fromDer(der);
    }
}
