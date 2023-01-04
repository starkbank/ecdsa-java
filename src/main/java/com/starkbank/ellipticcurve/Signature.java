package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.Binary;
import com.starkbank.ellipticcurve.utils.Der;
import com.starkbank.ellipticcurve.utils.Der.DerFieldType;
import java.math.BigInteger;
import java.util.Arrays;


public class Signature {

    public BigInteger r;
    public BigInteger s;
    public BigInteger recoveryId;

    /**
     *
     * @param r r
     * @param s s
     */
    public Signature(BigInteger r, BigInteger s, BigInteger recoveryId) {
        this.r = r;
        this.s = s;
        this.recoveryId = recoveryId;
    }

    public Signature(BigInteger r, BigInteger s) {
        this(r, s, null);
    }

    public byte[] toDer(Boolean withRecoveryId) {
        String hexadecimal = this._toString();
        byte[] encodedSequence = Binary.byteFromHex(hexadecimal);
        if(!withRecoveryId) return encodedSequence;

        byte[] finalEncodedSequence = new byte[encodedSequence.length + 1];
        finalEncodedSequence[0] = (byte) (27 + this.recoveryId.intValue());
        for (int i = 0; i < encodedSequence.length; i++) {
            finalEncodedSequence[i + 1] = encodedSequence[i];
        }
        return finalEncodedSequence;
    }

    public byte[] toDer() {
        return this.toDer(false);
    }

    public String toBase64(Boolean withRecoveryId) {
        return Binary.base64FromByte(this.toDer(withRecoveryId));
    }

    public String toBase64() {
        return this.toBase64(false);
    }

    public static Signature fromDer(byte[] der, Boolean recoveryByte) throws Exception {
        BigInteger recoveryId = null;
        if (recoveryByte) {
            recoveryId = BigInteger.valueOf(der[0]);
            recoveryId = recoveryId.subtract(BigInteger.valueOf(27));
            der = Arrays.copyOfRange(der, 1, der.length);
        }

        String hexadecimal = Binary.hexFromByte(der);
        return Signature._fromString(hexadecimal, recoveryId);
    }

    public static Signature fromDer(byte[] der) throws Exception {
        return Signature.fromDer(der, false);
    }

    public static Signature fromBase64(String string, Boolean recoveryByte) throws Exception {
        byte[] der = Binary.byteFromBase64(string);
        return Signature.fromDer(der, recoveryByte);
    }

    public static Signature fromBase64(String string) throws Exception {
        return Signature.fromBase64(string, false);
    }

    public String _toString() {
        return Der.encodeConstructed(
            Der.encodePrimitive(DerFieldType.Integer, this.r.toString()),
            Der.encodePrimitive(DerFieldType.Integer, this.s.toString())
        );
    }

    public static Signature _fromString(String string, BigInteger recoveryId) throws Exception {
        Object[] parsed = (Object[]) Der.parse(string)[0];
        BigInteger r = new BigInteger(parsed[0].toString());
        Object[] parsedS = (Object[]) parsed[1];
        BigInteger s = new BigInteger(parsedS[0].toString());
        return new Signature(r, s, recoveryId);
    }

    public static Signature _fromString(String string) throws Exception {
        return Signature._fromString(string, null);
    }

}
