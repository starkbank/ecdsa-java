package com.starkbank.ellipticcurve;
import org.junit.Test;
import static org.junit.Assert.assertEquals;


public class CompPublicKeyTest {

    @Test
    public void testBatch() throws Exception {
        for(int i = 0; i < 1000; i++) {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            String publicKeyString = publicKey.toCompressed();

            PublicKey recoveredPublicKey = PublicKey.fromCompressed(publicKeyString);

            assertEquals(publicKey.point.x, recoveredPublicKey.point.x);
            assertEquals(publicKey.point.y, recoveredPublicKey.point.y);
        }
    }

    @Test
    public void testFromCompressedEven() throws Exception {
        String publicKeyCompressed = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2";
        PublicKey publicKey = PublicKey.fromCompressed(publicKeyCompressed);
        assertEquals(publicKey.toPem(), "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----");
    }

    @Test
    public void testFromCompressedOdd() throws Exception {
        String publicKeyCompressed = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50";
        PublicKey publicKey = PublicKey.fromCompressed(publicKeyCompressed);
        assertEquals(publicKey.toPem(), "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----");
    }

    @Test
    public void testToCompressedEven() throws Exception {
        PublicKey publicKey = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----");
        String publicKeyCompressed = publicKey.toCompressed();
        assertEquals(publicKeyCompressed, "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2");
    }

    @Test
    public void testToCompressedOdd() throws Exception {
        PublicKey publicKey = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----");
        String publicKeyCompressed = publicKey.toCompressed();
        assertEquals(publicKeyCompressed, "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50");
    }
}
