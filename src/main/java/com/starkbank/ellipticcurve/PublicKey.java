package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.Der;
import com.starkbank.ellipticcurve.utils.Pem;
import com.starkbank.ellipticcurve.utils.Der.DerFieldType;
import com.starkbank.ellipticcurve.utils.Binary;
import static com.starkbank.ellipticcurve.Curve.secp256k1;
import java.math.BigInteger;
import java.util.Arrays;


public class PublicKey {

    public Point point;
    public Curve curve;
    private static final String pemTemplate = "-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----";
    private static final long[] ecdsaPublicKeyOid = {1, 2, 840, 10045, 2, 1};
    private static final String evenTag = "02";
    private static final String oddTag = "03";

    /**
     *
     * @param point point
     * @param curve curve
     */
    public PublicKey(Point point, Curve curve) {
        this.point = point;
        this.curve = curve;
    }

    /**
     *
     * @return String
     */
    public String toString() {
        return toString(false);
    }

    /**
     *
     * @param encoded encoded
     * @return string
     */
    public String toString(boolean encoded) {
        int baseLength = 2 * this.curve.length();
        String xHex = Binary.padLeftZeros(Binary.hexFromInt(this.point.x), baseLength);
        String yHex = Binary.padLeftZeros(Binary.hexFromInt(this.point.y), baseLength);
        String string = xHex + yHex;
        if (encoded) {
            return "0004" + string;
        }
        return string;
    }

    public String toCompressed() {
        int baseLength = 2 * this.curve.length();
        String parityTag = oddTag;
        if (point.y.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            parityTag = evenTag;
        }
        String xHex = Binary.padLeftZeros(Binary.hexFromInt(point.x), baseLength);
        return parityTag + xHex;
    }

    /**
     *
     * @return string
     */
    public byte[] toDer() {
        String hexadecimal = Der.encodeConstructed(
            Der.encodeConstructed(
                Der.encodePrimitive(DerFieldType.Object, ecdsaPublicKeyOid),
                Der.encodePrimitive(DerFieldType.Object, this.curve.oid)
            ),    
            Der.encodePrimitive(DerFieldType.BitString, this.toString(true))
        );
        return Binary.byteFromHex(hexadecimal);
    }

    /**
     *
     * @return String
     */
    public String toPem() {
        byte[] der = this.toDer();
        return Pem.createPem(Binary.base64FromByte(der), pemTemplate);
    }

    public static PublicKey fromPem(String string) throws Exception{
        String publicKeyPem = Pem.getPemContent(string, pemTemplate);
        return fromDer(Binary.byteFromBase64(publicKeyPem));
    }

    public static PublicKey fromDer(byte[] der) throws Exception{
        String hexadecimal = Binary.hexFromByte(der);
        Object[] parsed = (Object[]) Der.parse(hexadecimal)[0];
        Object[] curveData = (Object[]) parsed[0];
        String pointString = parsed[1].toString();
        long[] publicKeyOid = Binary.longFromString(curveData[0].toString());
        Object[] curveOidObject = (Object[]) curveData[1];
        long[] curveOid = Binary.longFromString(curveOidObject[0].toString());

        if (!Arrays.equals(publicKeyOid, ecdsaPublicKeyOid)) {
            throw new Exception("The Public Key Object Identifier (OID) should be " + Arrays.toString(ecdsaPublicKeyOid) + ", but " + Arrays.toString(publicKeyOid) + " was found instead");
        }
        Curve curve = Curve.getByOid(curveOid);
        return fromString((String) pointString, curve);
    }

    public static PublicKey fromString(String string) {
        return fromString(string, secp256k1);
    }

    public static PublicKey fromString(String string, Curve curve){
        return fromString(string, curve, false);
    }

    public static PublicKey fromString(String string, Curve curve, Boolean ValidatePoint) {
        int baseLength = 2 * curve.length();
        if (string.length() > 2 * baseLength && string.substring(0, 4).equals("0004")) {
            string = string.substring(4);
        }

        String xs = string.substring(0, baseLength);
        String ys = string.substring(baseLength);

        Point p = new Point(
            Binary.intFromHex(xs),
            Binary.intFromHex(ys)
        );

        PublicKey publicKey = new PublicKey(p, curve);
        if (!ValidatePoint) {
            return publicKey;
        }
        if (p.isAtInfinity()){
            throw new RuntimeException("Public Key point is at infinity");
        }
        if (!curve.contains(p)) {
            throw new RuntimeException("Point (" + p.x + "," + p.y + " is not valid for curve " + curve.name);
        }
        if (!Math.multiply(p, curve.N, curve.N, curve.A, curve.P).isAtInfinity()){
            throw new RuntimeException("Point (" + p.x + "," + p.y + ") * " + curve.name + ".N is not infinity");
        }
        return publicKey;
    }

    public static PublicKey fromCompressed(String string) {
        return fromCompressed(string, secp256k1);
    }

    public static PublicKey fromCompressed(String string, Curve curve) {
        String parityTag = string.substring(0, 2);
        String xHex = string.substring(2);
        BigInteger x = Binary.intFromHex(xHex);
        BigInteger y = curve.y(x, parityTag.equals(evenTag));
        Point p = new Point(x, y);
        return new PublicKey(p, curve);
    }
}
