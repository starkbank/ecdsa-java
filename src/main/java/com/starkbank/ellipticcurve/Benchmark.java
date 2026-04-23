package com.starkbank.ellipticcurve;


public class Benchmark {

    private static final int ROUNDS = 100;

    public static void main(String[] args) {
        PrivateKey privateKey = new PrivateKey();
        PublicKey publicKey = privateKey.publicKey();
        String message = "This is a benchmark test message";

        // Warmup
        Signature sig = Ecdsa.sign(message, privateKey);
        Ecdsa.verify(message, sig, publicKey);

        // Benchmark sign
        long start = System.nanoTime();
        for (int i = 0; i < ROUNDS; i++) {
            sig = Ecdsa.sign(message, privateKey);
        }
        double signTime = (System.nanoTime() - start) / 1e6 / ROUNDS;

        // Benchmark verify
        start = System.nanoTime();
        for (int i = 0; i < ROUNDS; i++) {
            Ecdsa.verify(message, sig, publicKey);
        }
        double verifyTime = (System.nanoTime() - start) / 1e6 / ROUNDS;

        System.out.println();
        System.out.printf("starkbank-ecdsa benchmark (%d rounds)%n", ROUNDS);
        System.out.println("---------------------------------------");
        System.out.printf("sign:    %.1fms%n", signTime);
        System.out.printf("verify:  %.1fms%n", verifyTime);
        System.out.println();
    }
}
