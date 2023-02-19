package com.eatthepath.hkdf;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.function.Supplier;

public class HKDF {

    private final Supplier<Mac> hmacSupplier;
    private final Key defaultSalt;

    @FunctionalInterface
    private interface MacSupplier {
        Mac get() throws NoSuchAlgorithmException, NoSuchProviderException;
    }

    public HKDF(final String algorithm) throws NoSuchAlgorithmException {
        final Supplier<Mac> hmacSupplier;

        try {
            hmacSupplier = buildHmacSupplier(() -> Mac.getInstance(algorithm));
        } catch (final NoSuchProviderException e) {
            // This can never happen because we're not trying to find a provider by name
            throw new AssertionError("Failed to find provider, but no provider name specified", e);
        }

        this.hmacSupplier = hmacSupplier;
        this.defaultSalt = buildDefaultSalt(hmacSupplier.get());
    }

    public HKDF(final String algorithm, final String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {

        this.hmacSupplier = buildHmacSupplier(() -> Mac.getInstance(algorithm, provider));
        this.defaultSalt = buildDefaultSalt(hmacSupplier.get());
    }

    public HKDF(final String algorithm, final Provider provider) throws NoSuchAlgorithmException {
        final Supplier<Mac> hmacSupplier;

        try {
            hmacSupplier = buildHmacSupplier(() -> Mac.getInstance(algorithm, provider));
        } catch (final NoSuchProviderException e) {
            // This can never happen because we're not trying to find a provider by name
            throw new AssertionError("Failed to find provider, but no provider name specified", e);
        }

        this.hmacSupplier = hmacSupplier;
        this.defaultSalt = buildDefaultSalt(hmacSupplier.get());
    }

    private static Supplier<Mac> buildHmacSupplier(final MacSupplier baseSupplier)
            throws NoSuchAlgorithmException, NoSuchProviderException {

        final Mac prototypeMac = baseSupplier.get();

        try {
            // Cloning a prototype Mac is almost always the most efficient way to get a new Mac instance
            prototypeMac.clone();

            return () -> {
                try {
                    return (Mac) prototypeMac.clone();
                } catch (final CloneNotSupportedException e) {
                    // We just cloned the prototype successfully, so we know this can never happen
                    throw new AssertionError("Previously-cloneable Mac instances must remain cloneable");
                }
            };
        } catch (final CloneNotSupportedException e) {
            return () -> {
                try {
                    return baseSupplier.get();
                } catch (final NoSuchAlgorithmException | NoSuchProviderException ex) {
                    // We were able to create the prototype Mac earlier, so this can never happen
                    throw new AssertionError("Previously-legal algorithms/providers must remain legal");
                }
            };
        }
    }

    private static Key buildDefaultSalt(final Mac hmac) {
        return new SecretKeySpec(new byte[hmac.getMacLength()], hmac.getAlgorithm());
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
        return hmacSupplier.get().getAlgorithm();
    }

    public byte[] deriveKey(final byte[] inputKeyMaterial,
                            final byte[] salt,
                            final byte[] info,
                            final int outputKeyLength) {

        final Mac hmac = hmacSupplier.get();
        final Key pseudoRandomKey = extractPseudoRandomKey(inputKeyMaterial, salt, hmac);

        return deriveKey(pseudoRandomKey, info, outputKeyLength, hmac);
    }

    public byte[] deriveKey(final byte[] pseudoRandomKey,
                            final byte[] info,
                            final int outputKeyLength) {

        final Mac hmac = hmacSupplier.get();

        return deriveKey(new SecretKeySpec(pseudoRandomKey, hmac.getAlgorithm()),
                info,
                outputKeyLength,
                hmac);
    }

    private byte[] deriveKey(final Key pseudoRandomKey,
                             final byte[] info,
                             final int outputKeyLength,
                             final Mac hmac) {

        if (outputKeyLength < 1) {
            throw new IllegalArgumentException("Output key length must be positive");
        }

        final int macLength = hmac.getMacLength();

        if (outputKeyLength > 255 * macLength) {
            throw new IllegalArgumentException(
                    "Output key length with " + hmac.getAlgorithm() +
                            " must be no more than " + (255 * macLength) + " bytes");
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

        return extractPseudoRandomKey(inputKeyMaterial, salt, hmacSupplier.get()).getEncoded();
    }

    private Key extractPseudoRandomKey(final byte[] inputKeyMaterial,
                                       final byte[] salt,
                                       final Mac hmac) {

        try {
            hmac.init(salt != null && salt.length != 0 ? new SecretKeySpec(salt, hmac.getAlgorithm()) : defaultSalt);
            return new SecretKeySpec(hmac.doFinal(inputKeyMaterial), hmac.getAlgorithm());
        } catch (final InvalidKeyException e) {
            // Practically, this should never happen for any hashing algorithm (barring zero-length input key material)
            throw new IllegalArgumentException(e);
        }
    }
}
