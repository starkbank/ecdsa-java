package com.starkbank.ellipticcurve;

import org.junit.Test;
import static org.junit.Assert.assertEquals;


public class CompPubKeyTest {

    @Test
    public void testBatch() {
        for (int i = 0; i < 100; i++) {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            String publicKeyString = publicKey.toCompressed();

            PublicKey recoveredPublicKey = PublicKey.fromCompressed(publicKeyString, publicKey.curve);

            assertEquals(publicKey.point.x, recoveredPublicKey.point.x);
            assertEquals(publicKey.point.y, recoveredPublicKey.point.y);
        }
    }

    @Test
    public void testFromCompressedEven() {
        String publicKeyCompressed = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2";
        PublicKey publicKey = PublicKey.fromCompressed(publicKeyCompressed);
        String pem = publicKey.toPem();
        assertEquals(
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\n" +
            "sJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n" +
            "-----END PUBLIC KEY-----\n",
            pem
        );
    }

    @Test
    public void testFromCompressedOdd() {
        String publicKeyCompressed = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50";
        PublicKey publicKey = PublicKey.fromCompressed(publicKeyCompressed);
        String pem = publicKey.toPem();
        assertEquals(
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n" +
            "61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n" +
            "-----END PUBLIC KEY-----\n",
            pem
        );
    }

    @Test
    public void testToCompressedEven() {
        PublicKey publicKey = PublicKey.fromPem(
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\n" +
            "sJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n" +
            "-----END PUBLIC KEY-----"
        );
        String publicKeyCompressed = publicKey.toCompressed();
        assertEquals("0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2", publicKeyCompressed);
    }

    @Test
    public void testToCompressedOdd() {
        PublicKey publicKey = PublicKey.fromPem(
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n" +
            "61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n" +
            "-----END PUBLIC KEY-----"
        );
        String publicKeyCompressed = publicKey.toCompressed();
        assertEquals("0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50", publicKeyCompressed);
    }
}
