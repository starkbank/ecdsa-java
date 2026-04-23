package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.Base64;
import com.starkbank.ellipticcurve.utils.BinaryAscii;
import com.starkbank.ellipticcurve.utils.ByteString;
import com.starkbank.ellipticcurve.utils.Der;
import java.io.IOException;
import java.math.BigInteger;


public class Signature {

    public BigInteger r;
    public BigInteger s;
    public Integer recoveryId;

    /**
     * @param r r
     * @param s s
     */
    public Signature(BigInteger r, BigInteger s) {
        this(r, s, null);
    }

    /**
     * @param r r
     * @param s s
     * @param recoveryId recoveryId
     */
    public Signature(BigInteger r, BigInteger s, Integer recoveryId) {
        this.r = r;
        this.s = s;
        this.recoveryId = recoveryId;
    }

    /**
     * @return ByteString (DER encoded, without recovery ID)
     */
    public ByteString toDer() {
        return toDer(false);
    }

    /**
     * @param withRecoveryId whether to prepend the recovery ID byte
     * @return ByteString
     */
    public ByteString toDer(boolean withRecoveryId) {
        ByteString encodedSequence = Der.encodeSequence(Der.encodeInteger(r), Der.encodeInteger(s));
        if (!withRecoveryId) {
            return encodedSequence;
        }
        byte recoveryByte = (byte) (27 + this.recoveryId);
        byte[] seqBytes = encodedSequence.getBytes();
        byte[] result = new byte[1 + seqBytes.length];
        result[0] = recoveryByte;
        System.arraycopy(seqBytes, 0, result, 1, seqBytes.length);
        return new ByteString(result);
    }

    /**
     * @return String (base64 encoded, without recovery ID)
     */
    public String toBase64() {
        return toBase64(false);
    }

    /**
     * @param withRecoveryId whether to include the recovery ID byte
     * @return String (base64 encoded)
     */
    public String toBase64(boolean withRecoveryId) {
        return Base64.encodeBytes(toDer(withRecoveryId).getBytes());
    }

    /**
     * @param string byteString
     * @return Signature
     */
    public static Signature fromDer(ByteString string) {
        return fromDer(string, false);
    }

    /**
     * @param string byteString
     * @param recoveryByte whether the first byte is a recovery ID
     * @return Signature
     */
    public static Signature fromDer(ByteString string, boolean recoveryByte) {
        Integer recoveryId = null;
        if (recoveryByte) {
            recoveryId = (string.getShort(0)) - 27;
            string = string.substring(1);
        }

        ByteString[] str = Der.removeSequence(string);
        ByteString rs = str[0];
        ByteString empty = str[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER sig: %s", BinaryAscii.hexFromBinary(empty)));
        }
        Object[] o = Der.removeInteger(rs);
        BigInteger r = new BigInteger(o[0].toString());
        ByteString rest = (ByteString) o[1];
        o = Der.removeInteger(rest);
        BigInteger s = new BigInteger(o[0].toString());
        empty = (ByteString) o[1];
        if (!empty.isEmpty()) {
            throw new RuntimeException(String.format("trailing junk after DER numbers: %s", BinaryAscii.hexFromBinary(empty)));
        }
        return new Signature(r, s, recoveryId);
    }

    /**
     * @param string base64 encoded string
     * @return Signature
     */
    public static Signature fromBase64(ByteString string) {
        return fromBase64(string, false);
    }

    /**
     * @param string base64 encoded string
     * @param recoveryByte whether the first byte is a recovery ID
     * @return Signature
     */
    public static Signature fromBase64(ByteString string, boolean recoveryByte) {
        ByteString der;
        try {
            der = new ByteString(Base64.decode(string.getBytes()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Corrupted base64 string! Could not decode base64 from it");
        }
        return fromDer(der, recoveryByte);
    }

    /**
     * Convenience: fromBase64 from a plain String
     *
     * @param string base64 encoded string
     * @return Signature
     */
    public static Signature fromBase64(String string) {
        return fromBase64(new ByteString(string.getBytes()), false);
    }

    /**
     * Convenience: fromBase64 from a plain String with recovery byte option
     *
     * @param string base64 encoded string
     * @param recoveryByte whether the first byte is a recovery ID
     * @return Signature
     */
    public static Signature fromBase64(String string, boolean recoveryByte) {
        return fromBase64(new ByteString(string.getBytes()), recoveryByte);
    }
}
