package com.starkbank.ellipticcurve;

import com.starkbank.ellipticcurve.utils.ByteString;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Created on 21-Jan-19
 *
 * @author Taron Petrosyan
 */
public class PublicKeyTest {
    @Test
    public void testPemConversion() {
        PrivateKey privateKey = new PrivateKey();
        PublicKey publicKey1 = privateKey.publicKey();
        String pem = publicKey1.toPem();
        PublicKey publicKey2 = PublicKey.fromPem(pem);
        assertEquals(publicKey1.x, publicKey2.x);
        assertEquals(publicKey1.y, publicKey2.y);
        assertEquals(publicKey1.curve, publicKey2.curve);
    }

    @Test
    public void testDerConversion() {
        PrivateKey privateKey = new PrivateKey();
        PublicKey publicKey1 = privateKey.publicKey();
        ByteString der = publicKey1.toDer();
        PublicKey publicKey2 = PublicKey.fromDer(der);
        assertEquals(publicKey1.x, publicKey2.x);
        assertEquals(publicKey1.y, publicKey2.y);
        assertEquals(publicKey1.curve, publicKey2.curve);
    }

    @Test
    public void testStringConversion() {
        PrivateKey privateKey = new PrivateKey();
        PublicKey publicKey1 = privateKey.publicKey();
        ByteString string = publicKey1.toByteString();
        PublicKey publicKey2 = PublicKey.fromString(string);
        assertEquals(publicKey1.x, publicKey2.x);
        assertEquals(publicKey1.y, publicKey2.y);
        assertEquals(publicKey1.curve, publicKey2.curve);
    }

}
