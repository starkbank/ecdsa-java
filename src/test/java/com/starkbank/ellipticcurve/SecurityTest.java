package com.starkbank.ellipticcurve;

import org.junit.Before;
import org.junit.Test;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;


public class SecurityTest {

    // ===== Prime256v1PublicKeyDerivationTest (prime256v1/SHA-256) =====
    // RFC 6979 A.2.5 public key derivation. Signatures are hedged, so r/s
    // no longer match fixed test vectors, but pubkey derivation is unchanged.

    public static class Prime256v1PublicKeyDerivationTest {
        private PrivateKey privateKey;
        private PublicKey publicKey;

        @Before
        public void setUp() {
            privateKey = new PrivateKey(
                Curve.prime256v1,
                new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
            );
            publicKey = privateKey.publicKey();
        }

        @Test
        public void testPublicKeyMatchesRfc() {
            assertEquals(
                new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
                publicKey.point.x
            );
            assertEquals(
                new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16),
                publicKey.point.y
            );
        }

        @Test
        public void testSampleMessageRoundTrip() {
            Signature sig = Ecdsa.sign("sample", privateKey);
            assertTrue(sig.s.compareTo(Curve.prime256v1.N.shiftRight(1)) <= 0);
            assertTrue(Ecdsa.verify("sample", sig, publicKey));
        }

        @Test
        public void testTestMessageRoundTrip() {
            Signature sig = Ecdsa.sign("test", privateKey);
            assertTrue(sig.s.compareTo(Curve.prime256v1.N.shiftRight(1)) <= 0);
            assertTrue(Ecdsa.verify("test", sig, publicKey));
        }
    }

    // ===== Secp256k1PublicKeyDerivationTest =====
    // secp256k1 with secret=1 (pubkey = generator G).

    public static class Secp256k1PublicKeyDerivationTest {
        private PrivateKey privateKey;
        private PublicKey publicKey;

        @Before
        public void setUp() {
            privateKey = new PrivateKey(Curve.secp256k1, BigInteger.ONE);
            publicKey = privateKey.publicKey();
        }

        @Test
        public void testPublicKeyIsGenerator() {
            assertEquals(Curve.secp256k1.G.x, publicKey.point.x);
            assertEquals(Curve.secp256k1.G.y, publicKey.point.y);
        }

        @Test
        public void testSampleMessageRoundTrip() {
            Signature sig = Ecdsa.sign("sample", privateKey);
            assertTrue(Ecdsa.verify("sample", sig, publicKey));
        }

        @Test
        public void testTestMessageRoundTrip() {
            Signature sig = Ecdsa.sign("test", privateKey);
            assertTrue(Ecdsa.verify("test", sig, publicKey));
        }
    }

    // ===== MalleabilityTest =====

    public static class MalleabilityTest {

        @Test
        public void testSignAlwaysProducesLowS() {
            for (int i = 0; i < 100; i++) {
                PrivateKey privateKey = new PrivateKey();
                Signature signature = Ecdsa.sign("test message", privateKey);
                assertTrue(signature.s.compareTo(privateKey.curve.N.shiftRight(1)) <= 0);
            }
        }

        @Test
        public void testHighSSignatureStillVerifies() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            String message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey);
            Signature highS = new Signature(signature.r, privateKey.curve.N.subtract(signature.s));

            assertTrue(Ecdsa.verify(message, signature, publicKey));
            assertTrue(Ecdsa.verify(message, highS, publicKey));
        }
    }

    // ===== PublicKeyValidationTest =====

    public static class PublicKeyValidationTest {

        @Test
        public void testRejectOffCurvePublicKey() {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            String message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey);

            Point offCurvePoint = new Point(publicKey.point.x, publicKey.point.y.add(BigInteger.ONE));
            PublicKey offCurveKey = new PublicKey(offCurvePoint, publicKey.curve);

            assertFalse(Ecdsa.verify(message, signature, offCurveKey));
        }

        @Test(expected = RuntimeException.class)
        public void testFromStringRejectsOffCurvePoint() {
            PublicKey p = new PrivateKey().publicKey();
            int baseLength = 2 * p.curve.length();
            String badY = leftPad(p.point.y.add(BigInteger.ONE).toString(16), baseLength);
            String badHex = leftPad(p.point.x.toString(16), baseLength) + badY;
            PublicKey.fromString(badHex, p.curve);
        }

        @Test(expected = RuntimeException.class)
        public void testFromStringRejectsInfinityPoint() {
            int baseLength = 2 * Curve.secp256k1.length();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < baseLength * 2; i++) sb.append("0");
            String zeroHex = sb.toString();
            PublicKey.fromString(zeroHex, Curve.secp256k1);
        }

        private static String leftPad(String s, int length) {
            while (s.length() < length) s = "0" + s;
            return s;
        }
    }

    // ===== ForgeryAttemptTest =====

    public static class ForgeryAttemptTest {
        private PrivateKey privateKey;
        private PublicKey publicKey;
        private String message;
        private Signature signature;

        @Before
        public void setUp() {
            privateKey = new PrivateKey();
            publicKey = privateKey.publicKey();
            message = "authentic message";
            signature = Ecdsa.sign(message, privateKey);
        }

        @Test
        public void testRejectZeroSignature() {
            assertFalse(Ecdsa.verify(message, new Signature(BigInteger.ZERO, BigInteger.ZERO), publicKey));
        }

        @Test
        public void testRejectREqualsZero() {
            assertFalse(Ecdsa.verify(message, new Signature(BigInteger.ZERO, signature.s), publicKey));
        }

        @Test
        public void testRejectSEqualsZero() {
            assertFalse(Ecdsa.verify(message, new Signature(signature.r, BigInteger.ZERO), publicKey));
        }

        @Test
        public void testRejectREqualsN() {
            BigInteger N = publicKey.curve.N;
            assertFalse(Ecdsa.verify(message, new Signature(N, signature.s), publicKey));
        }

        @Test
        public void testRejectSEqualsN() {
            BigInteger N = publicKey.curve.N;
            assertFalse(Ecdsa.verify(message, new Signature(signature.r, N), publicKey));
        }

        @Test
        public void testRejectRExceedsN() {
            BigInteger N = publicKey.curve.N;
            assertFalse(Ecdsa.verify(message, new Signature(N.add(BigInteger.ONE), signature.s), publicKey));
        }

        @Test
        public void testRejectArbitrarySignature() {
            assertFalse(Ecdsa.verify(message, new Signature(BigInteger.ONE, BigInteger.ONE), publicKey));
        }

        @Test
        public void testRejectBoundarySignature() {
            BigInteger N = publicKey.curve.N;
            assertFalse(Ecdsa.verify(message, new Signature(N.subtract(BigInteger.ONE), N.subtract(BigInteger.ONE)), publicKey));
        }

        @Test
        public void testWrongKeyRejected() {
            PublicKey otherKey = new PrivateKey().publicKey();
            assertFalse(Ecdsa.verify(message, signature, otherKey));
        }
    }

    // ===== HedgedSignatureTest =====

    public static class HedgedSignatureTest {

        @Test
        public void testSameInputsProduceDifferentSignatures() {
            PrivateKey privateKey = new PrivateKey();
            String message = "test message";

            Signature signature1 = Ecdsa.sign(message, privateKey);
            Signature signature2 = Ecdsa.sign(message, privateKey);

            assertTrue(!signature1.r.equals(signature2.r) || !signature1.s.equals(signature2.s));
        }

        @Test
        public void testDifferentMessagesDifferentSignatures() {
            PrivateKey privateKey = new PrivateKey();

            Signature signature1 = Ecdsa.sign("message 1", privateKey);
            Signature signature2 = Ecdsa.sign("message 2", privateKey);

            assertTrue(!signature1.r.equals(signature2.r) || !signature1.s.equals(signature2.s));
        }

        @Test
        public void testDifferentKeysDifferentSignatures() {
            String message = "test message";

            Signature signature1 = Ecdsa.sign(message, new PrivateKey());
            Signature signature2 = Ecdsa.sign(message, new PrivateKey());

            assertTrue(!signature1.r.equals(signature2.r) || !signature1.s.equals(signature2.s));
        }
    }

    // ===== EdgeCaseMessageTest =====

    public static class EdgeCaseMessageTest {
        private PrivateKey privateKey;
        private PublicKey publicKey;

        @Before
        public void setUp() {
            privateKey = new PrivateKey();
            publicKey = privateKey.publicKey();
        }

        private void signAndVerify(String message) {
            Signature sig = Ecdsa.sign(message, privateKey);
            assertTrue(Ecdsa.verify(message, sig, publicKey));
            assertFalse(Ecdsa.verify(message + "x", sig, publicKey));
        }

        @Test
        public void testEmptyMessage() {
            signAndVerify("");
        }

        @Test
        public void testSingleCharMessage() {
            signAndVerify("a");
        }

        @Test
        public void testUnicodeMessage() {
            signAndVerify("\u00e9\u00e8\u00ea\u00eb");
        }

        @Test
        public void testEmojiMessage() {
            signAndVerify("\uD83D\uDD12\uD83D\uDD11");
        }

        @Test
        public void testNullByteMessage() {
            signAndVerify("before\0after");
        }

        @Test
        public void testLongMessage() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 10000; i++) sb.append("a");
            signAndVerify(sb.toString());
        }

        @Test
        public void testNewlinesAndWhitespace() {
            signAndVerify("  line1\n\tline2\r\n  ");
        }
    }

    // ===== SerializationRoundTripTest =====

    public static class SerializationRoundTripTest {
        private PrivateKey privateKey;
        private PublicKey publicKey;
        private String message;
        private Signature signature;

        @Before
        public void setUp() {
            privateKey = new PrivateKey();
            publicKey = privateKey.publicKey();
            message = "round-trip test";
            signature = Ecdsa.sign(message, privateKey);
        }

        @Test
        public void testSignatureDerRoundTrip() {
            com.starkbank.ellipticcurve.utils.ByteString der = signature.toDer();
            Signature restored = Signature.fromDer(der);
            assertEquals(restored.r, signature.r);
            assertEquals(restored.s, signature.s);
            assertTrue(Ecdsa.verify(message, restored, publicKey));
        }

        @Test
        public void testSignatureBase64RoundTrip() {
            String b64 = signature.toBase64();
            Signature restored = Signature.fromBase64(b64);
            assertEquals(restored.r, signature.r);
            assertEquals(restored.s, signature.s);
            assertTrue(Ecdsa.verify(message, restored, publicKey));
        }

        @Test
        public void testSignatureDerWithRecoveryIdRoundTrip() {
            com.starkbank.ellipticcurve.utils.ByteString der = signature.toDer(true);
            Signature restored = Signature.fromDer(der, true);
            assertEquals(restored.r, signature.r);
            assertEquals(restored.s, signature.s);
            assertEquals(restored.recoveryId, signature.recoveryId);
        }

        @Test
        public void testPrivateKeyPemRoundTrip() {
            String pem = privateKey.toPem();
            PrivateKey restored = PrivateKey.fromPem(pem);
            assertEquals(restored.secret, privateKey.secret);
            assertEquals(restored.curve.name, privateKey.curve.name);
        }

        @Test
        public void testPrivateKeyDerRoundTrip() {
            com.starkbank.ellipticcurve.utils.ByteString der = privateKey.toDer();
            PrivateKey restored = PrivateKey.fromDer(der);
            assertEquals(restored.secret, privateKey.secret);
        }

        @Test
        public void testPublicKeyPemRoundTrip() {
            String pem = publicKey.toPem();
            PublicKey restored = PublicKey.fromPem(pem);
            assertEquals(restored.point.x, publicKey.point.x);
            assertEquals(restored.point.y, publicKey.point.y);
        }

        @Test
        public void testPublicKeyCompressedRoundTrip() {
            String compressed = publicKey.toCompressed();
            PublicKey restored = PublicKey.fromCompressed(compressed, publicKey.curve);
            assertEquals(restored.point.x, publicKey.point.x);
            assertEquals(restored.point.y, publicKey.point.y);
            assertTrue(Ecdsa.verify(message, signature, restored));
        }

        @Test
        public void testPublicKeyCompressedEvenAndOdd() {
            for (int i = 0; i < 20; i++) {
                PrivateKey pk = new PrivateKey();
                PublicKey pub = pk.publicKey();
                String compressed = pub.toCompressed();
                PublicKey restored = PublicKey.fromCompressed(compressed, pub.curve);
                assertEquals(restored.point.x, pub.point.x);
                assertEquals(restored.point.y, pub.point.y);
            }
        }

        @Test
        public void testPrime256v1KeyRoundTrip() {
            PrivateKey pk = new PrivateKey(Curve.prime256v1, null);
            String pem = pk.toPem();
            PrivateKey restored = PrivateKey.fromPem(pem);
            assertEquals(restored.secret, pk.secret);
            assertEquals("prime256v1", restored.curve.name);
        }
    }

    // ===== TonelliShanksTest =====

    public static class TonelliShanksTest {

        @Test
        public void testPrimeCongruent1Mod4() {
            // P = 17: 17 - 1 = 16 = 2^4, S = 4, exercises full Tonelli-Shanks
            BigInteger P = BigInteger.valueOf(17);
            for (int value = 1; value < 17; value++) {
                BigInteger val = BigInteger.valueOf(value);
                BigInteger halfP = P.subtract(BigInteger.ONE).divide(BigInteger.TWO);
                if (val.modPow(halfP, P).equals(BigInteger.ONE)) {
                    BigInteger root = Math.modularSquareRoot(val, P);
                    assertEquals(val, root.multiply(root).mod(P));
                }
            }
        }

        @Test
        public void testPrimeCongruent5Mod8() {
            // P = 13: 13 - 1 = 12 = 3 * 2^2, S = 2
            BigInteger P = BigInteger.valueOf(13);
            for (int value = 1; value < 13; value++) {
                BigInteger val = BigInteger.valueOf(value);
                BigInteger halfP = P.subtract(BigInteger.ONE).divide(BigInteger.TWO);
                if (val.modPow(halfP, P).equals(BigInteger.ONE)) {
                    BigInteger root = Math.modularSquareRoot(val, P);
                    assertEquals(val, root.multiply(root).mod(P));
                }
            }
        }

        @Test
        public void testPrimeCongruent3Mod4() {
            // P = 7: fast path (S = 1)
            BigInteger P = BigInteger.valueOf(7);
            for (int value = 1; value < 7; value++) {
                BigInteger val = BigInteger.valueOf(value);
                BigInteger halfP = P.subtract(BigInteger.ONE).divide(BigInteger.TWO);
                if (val.modPow(halfP, P).equals(BigInteger.ONE)) {
                    BigInteger root = Math.modularSquareRoot(val, P);
                    assertEquals(val, root.multiply(root).mod(P));
                }
            }
        }

        @Test
        public void testZeroValue() {
            assertEquals(BigInteger.ZERO, Math.modularSquareRoot(BigInteger.ZERO, BigInteger.valueOf(17)));
        }
    }

    // ===== HashTruncationTest =====

    public static class HashTruncationTest {

        @Test
        public void testSignVerifyWithSha512() throws NoSuchAlgorithmException {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            String message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey, MessageDigest.getInstance("SHA-512"));

            assertTrue(Ecdsa.verify(message, signature, publicKey, MessageDigest.getInstance("SHA-512")));
            assertFalse(Ecdsa.verify("wrong message", signature, publicKey, MessageDigest.getInstance("SHA-512")));
        }

        @Test
        public void testSha512SignaturesAreHedged() throws NoSuchAlgorithmException {
            PrivateKey privateKey = new PrivateKey();
            String message = "test message";

            Signature signature1 = Ecdsa.sign(message, privateKey, MessageDigest.getInstance("SHA-512"));
            Signature signature2 = Ecdsa.sign(message, privateKey, MessageDigest.getInstance("SHA-512"));

            assertTrue(!signature1.r.equals(signature2.r) || !signature1.s.equals(signature2.s));
        }

        @Test
        public void testHashMismatchFails() throws NoSuchAlgorithmException {
            PrivateKey privateKey = new PrivateKey();
            PublicKey publicKey = privateKey.publicKey();
            String message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey, MessageDigest.getInstance("SHA-256"));
            assertFalse(Ecdsa.verify(message, signature, publicKey, MessageDigest.getInstance("SHA-512")));
        }
    }

    // ===== Prime256v1SecurityTest =====

    public static class Prime256v1SecurityTest {

        @Test
        public void testSignVerify() {
            PrivateKey privateKey = new PrivateKey(Curve.prime256v1, null);
            PublicKey publicKey = privateKey.publicKey();
            String message = "test message";

            Signature signature = Ecdsa.sign(message, privateKey);

            assertTrue(signature.s.compareTo(Curve.prime256v1.N.shiftRight(1)) <= 0);
            assertTrue(Ecdsa.verify(message, signature, publicKey));
        }

        @Test
        public void testSignaturesAreHedged() {
            PrivateKey privateKey = new PrivateKey(Curve.prime256v1, null);
            String message = "test message";

            Signature signature1 = Ecdsa.sign(message, privateKey);
            Signature signature2 = Ecdsa.sign(message, privateKey);

            assertTrue(!signature1.r.equals(signature2.r) || !signature1.s.equals(signature2.s));
        }

        @Test
        public void testWrongCurveKeyFails() {
            PrivateKey k1Key = new PrivateKey(Curve.secp256k1, null);
            PrivateKey p256Key = new PrivateKey(Curve.prime256v1, null);
            String message = "cross-curve test";

            Signature sig = Ecdsa.sign(message, k1Key);
            assertFalse(Ecdsa.verify(message, sig, p256Key.publicKey()));
        }
    }
}
