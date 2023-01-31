package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.Der;
import com.starkbank.ellipticcurve.utils.Pem;
import com.starkbank.ellipticcurve.utils.Binary;
import com.starkbank.ellipticcurve.utils.RandomInteger;
import com.starkbank.ellipticcurve.utils.Der.DerFieldType;
import java.math.BigInteger;


public class PrivateKey {

    public Curve curve;
    public BigInteger secret;
    private static final String pemTemplate = "-----BEGIN EC PRIVATE KEY-----\n%s-----END EC PRIVATE KEY-----";

    /**
     *
     */
    public PrivateKey() {
        this(Curve.secp256k1, null);
        secret = RandomInteger.between(BigInteger.ONE, curve.N.subtract(BigInteger.ONE));
    }
    
    /**
     *
     * @param curve curve
     */
    public PrivateKey(Curve curve) {
        this(curve, RandomInteger.between(BigInteger.ONE, curve.N.subtract(BigInteger.ONE)));
    }

    /**
     *
     * @param secret secret
     */
    public PrivateKey(BigInteger secret) {
        this(Curve.secp256k1, secret);
    }

    /**
     *
     * @param curve curve
     * @param secret secret
     */
    public PrivateKey(Curve curve, BigInteger secret) {
        this.curve = curve;
        this.secret = secret;
    }

    /**
     *
     * @return PublicKey
     */
    public PublicKey publicKey() {
        Curve curve = this.curve;
        Point publicPoint = Math.multiply(curve.G, this.secret, curve.N, curve.A, curve.P);
        return new PublicKey(publicPoint, curve);
    }

    public String toString() {
        return Binary.hexFromInt(secret);
    }

    public byte[] toDer() {
        String publicKeyString = this.publicKey().toString(true);
        String hexadecimal = Der.encodeConstructed(
            Der.encodePrimitive(DerFieldType.Integer, "1"),
            Der.encodePrimitive(DerFieldType.OctetString, Binary.hexFromInt(this.secret)),
            Der.encodePrimitive(DerFieldType.OidContainer, Der.encodePrimitive(DerFieldType.Object, this.curve.oid)),
            Der.encodePrimitive(DerFieldType.PublicKeyPointContainer, Der.encodePrimitive(DerFieldType.BitString, publicKeyString))
        );
        return Binary.byteFromHex(hexadecimal);
    }

    public String toPem() {
        byte[] der = this.toDer();
        return Pem.createPem(Binary.base64FromByte(der), pemTemplate);
    }

    public static PrivateKey fromPem(String pem) throws Exception {
        String privateKeyPem = Pem.getPemContent(pem, pemTemplate);
        byte[] der = Binary.byteFromBase64(privateKeyPem);
        return fromDer(der);
    }

    public static PrivateKey fromDer(byte[] der) throws Exception {
        String hexadecimal = Binary.hexFromByte(der);
        Object[] parsed = (Object[]) Der.parse(hexadecimal)[0];

        int privateKeyFlag = Integer.parseInt(parsed[0].toString());
        Object[] parsedObject = (Object[]) parsed[1];

        String secretHex = parsedObject[0].toString();
        Object[] parsedObject1 = (Object[]) parsedObject[1];

        Object[] curveDataObject = (Object[]) parsedObject1[0];
        long[] curveData = Binary.longFromString(curveDataObject[0].toString());
        
        Object[] publicKeyStringObject = (Object[]) parsedObject1[1];
        String publicKeyString = publicKeyStringObject[0].toString().toLowerCase();

        if (privateKeyFlag != 1){
            throw new Exception("Private keys should start with a '1' flag, but a " + privateKeyFlag + " was found instead");
        }

        Curve curve = Curve.getByOid(curveData);
        PrivateKey privateKey = PrivateKey.fromString(secretHex, curve);
        if (!privateKey.publicKey().toString(true).equals(publicKeyString)){
            throw new Exception("The public key described inside the private key file doesn't match the actual public key of the pair");
        }

        return privateKey;
    }

    public static PrivateKey fromString(String string, Curve curve){
        return new PrivateKey(curve, Binary.intFromHex(string));
    }

    public static PrivateKey fromString(String string){
        Curve curve = Curve.secp256k1;
        return fromString(string, curve);
    }
}
