package com.starkbank.ellipticcurve;

import com.starkbank.ellipticcurve.utils.ByteString;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;


public class SignatureTest {

    @Test
    public void testDerConversion() {
        PrivateKey privateKey = new PrivateKey();
        String message = "This is a text message";

        Signature signature1 = Ecdsa.sign(message, privateKey);

        ByteString der = signature1.toDer();

        Signature signature2 = Signature.fromDer(der);

        assertEquals(signature1.r, signature2.r);
        assertEquals(signature1.s, signature2.s);
    }

    @Test
    public void testBase64Conversion() {
        PrivateKey privateKey = new PrivateKey();
        String message = "This is a text message";

        Signature signature1 = Ecdsa.sign(message, privateKey);

        String base64 = signature1.toBase64();

        Signature signature2 = Signature.fromBase64(base64);

        assertEquals(signature1.r, signature2.r);
        assertEquals(signature1.s, signature2.s);
    }

    @Test
    public void testUniqueness() {
        PrivateKey privateKey = new PrivateKey();
        String message = "This is a text message";

        Signature signature1 = Ecdsa.sign(message, privateKey);
        Signature signature2 = Ecdsa.sign(message, privateKey);

        assertNotEquals(signature1.toBase64(), signature2.toBase64());
    }
}
