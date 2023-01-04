package com.starkbank.ellipticcurve;
import org.junit.Test;
import static org.junit.Assert.assertTrue;
import java.math.BigInteger;


public class CurveTest {

    @Test
    public void testPemConversion() throws Exception {
        Curve newCurve = new Curve(
            BigInteger.ZERO,
            BigInteger.valueOf(7),
            new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
            new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
            new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
            new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
            "secp256k1",
            new long[]{1, 3, 132, 0, 10}
        );

        PrivateKey privateKey1 = new PrivateKey(newCurve);
        PublicKey publicKey1 = privateKey1.publicKey();

        String privateKeyPem = privateKey1.toPem();
        String publicKeyPem = publicKey1.toPem();

        PrivateKey privateKey2 = PrivateKey.fromPem(privateKeyPem);
        PublicKey publicKey2 = PublicKey.fromPem(publicKeyPem);

        String message = "test";

        String signatureBase64 = Ecdsa.sign(message, privateKey2).toBase64();
        Signature signature = Signature.fromBase64(signatureBase64);

        assertTrue(Ecdsa.verify(message, signature, publicKey2));
    }

    @Test
    public void testAddNewCurve() throws Exception {
        Curve newCurve = new Curve(
            new BigInteger("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00", 16),
            new BigInteger("ee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f", 16),
            new BigInteger("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03", 16),
            new BigInteger("f1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1", 16),
            new BigInteger("b6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff", 16),
            new BigInteger("6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb", 16),
            "frp256v1",
            new long[]{1, 2, 250, 1, 223, 101, 256, 1}
        );
        Curve.add(newCurve);
        PrivateKey privateKey1 = new PrivateKey(newCurve);
        PublicKey publicKey1 = privateKey1.publicKey();

        String privateKeyPem = privateKey1.toPem();
        String publicKeyPem = publicKey1.toPem();

        PrivateKey privateKey2 = PrivateKey.fromPem(privateKeyPem);
        PublicKey publicKey2 = PublicKey.fromPem(publicKeyPem);

        String message = "test";

        String signatureBase64 = Ecdsa.sign(message, privateKey2).toBase64();
        Signature signature = Signature.fromBase64(signatureBase64);

        assertTrue(Ecdsa.verify(message, signature, publicKey2));
    }

    @Test
    public void testUnsupportedCurve() throws Exception {
        Curve newCurve = new Curve(
            new BigInteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374", 16),
            new BigInteger("662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04", 16),
            new BigInteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16),
            new BigInteger("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16),
            new BigInteger("a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4", 16),
            new BigInteger("2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be", 16),
            "brainpoolP256t1",
            new long[]{1, 3, 36, 3, 3, 2, 8, 1, 1, 8}
        );

        PrivateKey privateKey1 = new PrivateKey(newCurve);
        PublicKey publicKey1 = privateKey1.publicKey();

        String privateKeyPem = privateKey1.toPem();
        String publicKeyPem = publicKey1.toPem();

        try {
            PrivateKey privateKey2 = PrivateKey.fromPem(privateKeyPem);
        } catch (Error e) {
            assertTrue(e.getMessage().contains("Unknown curve"));
        }

        try {
            PublicKey publicKey2 = PublicKey.fromPem(publicKeyPem);
        } catch (Error e) {
            assertTrue(e.getMessage().contains("Unknown curve"));
        }
    }
}
