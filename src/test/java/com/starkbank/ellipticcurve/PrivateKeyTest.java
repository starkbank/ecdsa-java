package com.starkbank.ellipticcurve;
import com.starkbank.ellipticcurve.utils.ByteString;
import org.junit.Test;
import static org.junit.Assert.assertEquals;


public class PrivateKeyTest {

    @Test
    public void  testPemConversion() {
        PrivateKey privateKey1 = new PrivateKey();
        String pem = privateKey1.toPem();
        PrivateKey privateKey2 = PrivateKey.fromPem(pem);
        assertEquals(privateKey1.secret, privateKey2.secret);
        assertEquals(privateKey1.curve, privateKey2.curve);
    }

    @Test
    public void testDerConversion() {
        PrivateKey privateKey1 = new PrivateKey();
        ByteString der = privateKey1.toDer();
        PrivateKey privateKey2 = PrivateKey.fromDer(der);
        assertEquals(privateKey1.secret, privateKey2.secret);
        assertEquals(privateKey1.curve, privateKey2.curve);
    }

    @Test
    public void  testStringConversion() {
        PrivateKey privateKey1 = new PrivateKey();
        ByteString string = privateKey1.toByteString();
        PrivateKey privateKey2 = PrivateKey.fromString(string);
        assertEquals(privateKey1.secret, privateKey2.secret);
        assertEquals(privateKey1.curve, privateKey2.curve);
    }
}
