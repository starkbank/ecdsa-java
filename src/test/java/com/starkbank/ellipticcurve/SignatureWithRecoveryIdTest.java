package com.starkbank.ellipticcurve;
import org.junit.Test;
import static org.junit.Assert.assertEquals;


public class SignatureWithRecoveryIdTest {

    @Test
    public void testDerConversion() throws Exception {
        PrivateKey privateKey = new PrivateKey();
        String message = "This is a text message";

        Signature signature1 = Ecdsa.sign(message, privateKey);

        byte[] der = signature1.toDer(true);

        Signature signature2 = Signature.fromDer(der, true);

        assertEquals(signature1.r, signature2.r);
        assertEquals(signature1.s, signature2.s);
        assertEquals(signature1.recoveryId, signature2.recoveryId);
    }

    @Test
    public void testBase64Conversion() throws Exception {
        PrivateKey privateKey = new PrivateKey();
        String message = "This is a text message";

        Signature signature1 = Ecdsa.sign(message, privateKey);

        String base64 = signature1.toBase64();

        Signature signature2 = Signature.fromBase64(base64);

        assertEquals(signature1.r, signature2.r);
        assertEquals(signature1.s, signature2.s);
    }
}
