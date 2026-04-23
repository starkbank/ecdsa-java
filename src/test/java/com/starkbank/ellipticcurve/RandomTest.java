package com.starkbank.ellipticcurve;

import org.junit.Test;
import static org.junit.Assert.assertTrue;


public class RandomTest {

    @Test
    public void testMany() {
        for (int i = 0; i < 100; i++) {
            PrivateKey privateKey1 = new PrivateKey();
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
    }
}
