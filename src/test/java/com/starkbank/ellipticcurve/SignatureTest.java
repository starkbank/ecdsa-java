package com.starkbank.ellipticcurve;
import org.junit.Test;
import static org.junit.Assert.assertEquals;


public class SignatureTest {

    @Test
    public void testDerConversion() throws Exception {
        PrivateKey privateKey = new PrivateKey();
        String message = "This is a text message";

        Signature signature1 = Ecdsa.sign(message, privateKey);

        byte[] der = signature1.toDer();

        Signature signature2 = Signature.fromDer(der);

        assertEquals(signature1.r, signature2.r);
        assertEquals(signature1.s, signature2.s);
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
