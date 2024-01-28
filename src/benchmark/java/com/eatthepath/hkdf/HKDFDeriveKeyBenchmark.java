package com.eatthepath.hkdf;

import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.util.Random;

@State(Scope.Benchmark)
public class HKDFDeriveKeyBenchmark {

    private HKDF hkdf;

    private byte[][] inputKeyMaterial;
    private byte[] salt;
    private byte[] info;

    private int i = 0;

    @Param({"16", "32", "77", "128", "8160"})
    public int outputKeyLength;

    private static final int INPUT_KEY_MATERIAL_ENTRIES = 16384;

    @Setup
    public void setUp() {
        hkdf = HKDF.withHmacSha256();

        inputKeyMaterial = new byte[INPUT_KEY_MATERIAL_ENTRIES][];

        final Random random = new Random();

        for (int i = 0; i < INPUT_KEY_MATERIAL_ENTRIES; i++) {
            inputKeyMaterial[i] = new byte[32];
            random.nextBytes(inputKeyMaterial[i]);
        }

        salt = new byte[32];
        random.nextBytes(salt);

        info = "benchmark".getBytes(StandardCharsets.UTF_8);
    }

    @Benchmark
    public byte[] deriveKey() {
        return hkdf.deriveKey(inputKeyMaterial[i++ % INPUT_KEY_MATERIAL_ENTRIES], salt, info, outputKeyLength);
    }
}
