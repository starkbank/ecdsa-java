package com.github.starkbank.ellipticcurve;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created on 13-Jan-19
 *
 * @author Taron Petrosyan
 */
public class EcdsaTest {
    @Test
    public void testVerifyRightMessage() {
        PrivateKey privateKey = new PrivateKey();
        PublicKey publicKey = privateKey.publicKey();

        String message = "This is the right message";

        Signature signature = Ecdsa.sign(message, privateKey);
        assertTrue(Ecdsa.verify(message, signature, publicKey));
    }

    @Test
    public void testVerifyWrongMessage() {
        PrivateKey privateKey = new PrivateKey();
        PublicKey publicKey = privateKey.publicKey();

        String message1 = "This is the right message";
        String message2 = "This is the wrong message";

        Signature signature = Ecdsa.sign(message1, privateKey);

        assertFalse(Ecdsa.verify(message2, signature, publicKey));
    }
}
