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

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] deriveKey(final byte[] inputKeyMaterial,
                            final byte[] salt,
                            final byte[] info,
                            final int outputKeyLength) {

        final Mac hmac;

        try {
            hmac = Mac.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            // We instantiated the Mac in the constructor; if it was legal then, it must be legal now
            throw new AssertionError("Previously-legal algorithms must remain legal");
        }

        return deriveKey(extractPseudoRandomKey(inputKeyMaterial, salt, hmac), info, outputKeyLength, hmac);
    }

    public byte[] deriveKey(final byte[] pseudoRandomKey,
                            final byte[] info,
                            final int outputKeyLength) {

        try {
            return deriveKey(new SecretKeySpec(pseudoRandomKey, algorithm),
                    info,
                    outputKeyLength,
                    Mac.getInstance(algorithm));
        } catch (final NoSuchAlgorithmException e) {
            // We instantiated the Mac in the constructor; if it was legal then, it must be legal now
            throw new AssertionError("Previously-legal algorithms must remain legal");
        }
    }

    private byte[] deriveKey(final Key pseudoRandomKey,
                             final byte[] info,
                             final int outputKeyLength,
                             final Mac hmac) {

        if (outputKeyLength < 1) {
            throw new IllegalArgumentException("Output key length must be positive");
        }

        if (outputKeyLength > 255 * macLength) {
            throw new IllegalArgumentException(
                    "Output key length with " + algorithm + " must be no more than " + (255 * macLength) + " bytes");
        }

        final int rounds = (outputKeyLength + macLength - 1) / macLength;
        final byte[] outputKey = new byte[rounds * macLength];

        try {
            hmac.init(pseudoRandomKey);
        } catch (final InvalidKeyException e) {
            // This should never happen; we just derived the key and know it's valid
            throw new AssertionError("Extracted keys must be valid");
        }

        try {
            hmac.update(info);
            hmac.update((byte) 1);
            hmac.doFinal(outputKey, 0);

            for (int round = 1; round < rounds; round++) {
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

    public byte[] extractPseudoRandomKey(final byte[] inputKeyMaterial,
                                         final byte[] salt) {

        try {
            return extractPseudoRandomKey(inputKeyMaterial, salt, Mac.getInstance(algorithm)).getEncoded();
        } catch (final NoSuchAlgorithmException e) {
            // We instantiated the Mac in the constructor; if it was legal then, it must be legal now
            throw new AssertionError("Previously-legal algorithms must remain legal");
        }
    }

    private Key extractPseudoRandomKey(final byte[] inputKeyMaterial,
                                       final byte[] salt,
                                       final Mac hmac) {

        try {
            hmac.init(salt != null && salt.length != 0 ? new SecretKeySpec(salt, algorithm) : defaultSalt);
            return new SecretKeySpec(hmac.doFinal(inputKeyMaterial), algorithm);
        } catch (final InvalidKeyException e) {
            // Practically, this should never happen for any hashing algorithm (barring zero-length input key material)
            throw new IllegalArgumentException(e);
        }
    }
}
