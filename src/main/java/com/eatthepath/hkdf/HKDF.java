package com.eatthepath.hkdf;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HKDF {

    private final String algorithm;
    private final int macLength;
    private final Key defaultSalt;

    public HKDF(final String algorithm) throws NoSuchAlgorithmException {
        final Mac hmac = Mac.getInstance(algorithm);

        this.algorithm = algorithm;
        this.macLength = hmac.getMacLength();
        this.defaultSalt = new SecretKeySpec(new byte[macLength], algorithm);
    }

    public static HKDF withHmacSha1() {
        try {
            return new HKDF("HmacSHA1");
        } catch (final NoSuchAlgorithmException e) {
            throw new AssertionError("All Java implementations are required to support HmacSHA1");
        }
    }

    public static HKDF withHmacSha256() {
        try {
            return new HKDF("HmacSHA256");
        } catch (final NoSuchAlgorithmException e) {
            throw new AssertionError("All Java implementations are required to support HmacSHA256");
        }
    }

    public byte[] deriveKey(final byte[] salt, final byte[] inputKeyMaterial, final int outputKeyLength, final byte[] info) {
        try {
            final Mac hmac = Mac.getInstance(algorithm);
            return expand(hmac, extract(hmac, salt, inputKeyMaterial), outputKeyLength, info);
        } catch (final NoSuchAlgorithmException e) {
            throw new AssertionError("Previously-legal algorithms must remain legal");
        }
    }

    public String getAlgorithm() {
        return algorithm;
    }

    byte[] extract(final Mac hmac, final byte[] salt, final byte[] inputKeyMaterial) {
        try {
            hmac.init(salt != null && salt.length != 0 ? new SecretKeySpec(salt, algorithm) : defaultSalt);
            return hmac.doFinal(inputKeyMaterial);
        } catch (final InvalidKeyException e) {
            // Technically, this can never happen because HmacSHA256 allows keys of any length even if very long keys
            // are "discouraged" and very short keys are "a terrible, terrible idea"
            throw new IllegalArgumentException(e);
        }
    }

    byte[] expand(final Mac hmac, final byte[] pseudoRandomKey, final int outputKeyLength, final byte[] info) {
        if (outputKeyLength > 255 * macLength) {
            throw new IllegalArgumentException("TODO");
        }

        final int rounds = (outputKeyLength + macLength - 1) / macLength;
        final byte[] outputKey = new byte[rounds * macLength];

        try {
            hmac.init(new SecretKeySpec(pseudoRandomKey, algorithm));
        } catch (final InvalidKeyException e) {
            // This should never happen; this method should only be called with keys derived from the extract() method
            throw new AssertionError("Extracted keys must be valid");
        }

        try {
            hmac.update(info);
            hmac.update((byte) 1);
            hmac.doFinal(outputKey, 0);

            for (byte round = 1; round < rounds; round++) {
                hmac.update(outputKey, (round - 1) * macLength, macLength);
                hmac.update(info);
                hmac.update((byte) (round + 1));
                hmac.doFinal(outputKey, round * macLength);
            }

            final byte[] truncatedKey = new byte[outputKeyLength];
            System.arraycopy(outputKey, 0, truncatedKey, 0, outputKeyLength);

            return truncatedKey;
        } catch (final ShortBufferException e) {
            // This should never happen; we control the buffer and can be confident we've allocated enough space
            throw new AssertionError(e);
        } finally {
            Arrays.fill(outputKey, (byte) 0);
        }
    }
}
