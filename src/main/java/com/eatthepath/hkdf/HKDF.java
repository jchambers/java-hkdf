package com.eatthepath.hkdf;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HKDF {

    static final String ALGORITHM_HMAC_SHA256 = "HmacSHA256";
    private static final int HMAC_LENGTH = 32;
    private static final Key DEFAULT_SALT = new SecretKeySpec(new byte[HMAC_LENGTH], ALGORITHM_HMAC_SHA256);

    public static byte[] deriveKey(final byte[] salt, final byte[] inputKeyMaterial, final int outputKeyLength, final byte[] info) {
        try {
            final Mac hmac = Mac.getInstance(ALGORITHM_HMAC_SHA256);
            return expand(hmac, extract(hmac, salt, inputKeyMaterial), outputKeyLength, info);
        } catch (final NoSuchAlgorithmException e) {
            throw new AssertionError("All Java implementations must support HmacSHA256");
        }
    }

    static byte[] extract(final Mac hmac, final byte[] salt, final byte[] inputKeyMaterial) {
        try {
            hmac.init(salt != null && salt.length != 0 ? new SecretKeySpec(salt, ALGORITHM_HMAC_SHA256) : DEFAULT_SALT);
            return hmac.doFinal(inputKeyMaterial);
        } catch (final InvalidKeyException e) {
            // Technically, this can never happen because HmacSHA256 allows keys of any length even if very long keys
            // are "discouraged" and very short keys are "a terrible, terrible idea"
            throw new IllegalArgumentException(e);
        }
    }

    static byte[] expand(final Mac hmac, final byte[] pseudoRandomKey, final int outputKeyLength, final byte[] info) {
        if (outputKeyLength > 255 * HMAC_LENGTH) {
            throw new IllegalArgumentException("TODO");
        }

        final int rounds = (outputKeyLength + HMAC_LENGTH - 1) / HMAC_LENGTH;
        final byte[] outputKey = new byte[rounds * HMAC_LENGTH];

        try {
            hmac.init(new SecretKeySpec(pseudoRandomKey, ALGORITHM_HMAC_SHA256));
        } catch (final InvalidKeyException e) {
            // This should never happen; this method should only be called with keys derived from the extract() method
            throw new AssertionError("Extracted keys must be valid");
        }

        try {
            hmac.update(info);
            hmac.update((byte) 1);
            hmac.doFinal(outputKey, 0);

            for (byte round = 1; round < rounds; round++) {
                hmac.update(outputKey, (round - 1) * HMAC_LENGTH, HMAC_LENGTH);
                hmac.update(info);
                hmac.update((byte) (round + 1));
                hmac.doFinal(outputKey, round * HMAC_LENGTH);
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
