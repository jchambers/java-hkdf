package com.eatthepath.hkdf;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.function.Supplier;

/**
 * Implements the Hashed Message Authentication Code (HMAC)-based key derivation function (HKDF) as specified in
 * <a href="https://datatracker.ietf.org/doc/html/rfc5869">IETF RFC&nbsp;5869</a>.
 * <p>
 * HKDF instances are thread-safe, and may be used by multiple threads without restriction.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5869">IETF RFC 5869 - HMAC-based Extract-and-Expand Key
 * Derivation Function (HKDF)</a>
 */
public class HKDF {

    private final Supplier<Mac> hmacSupplier;
    private final Key defaultSalt;

    @FunctionalInterface
    private interface MacSupplier {
        Mac get() throws NoSuchAlgorithmException, NoSuchProviderException;
    }

    /**
     * Constructs a new HKDF instance using the given HMAC algorithm.
     *
     * @param algorithm the name of the HMAC algorithm to use in the newly-constructed HKDF instance
     *
     * @throws NoSuchAlgorithmException if no security provider supports a {@code MacSpi} implementation for the
     * specified algorithm
     *
     * @see Mac#getInstance(String)
     */
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

    /**
     * Constructs a new HKDF instance using the given HMAC algorithm as implemented by the named security provider.
     *
     * @param algorithm the name of the HMAC algorithm to use in the newly-constructed HKDF instance
     * @param provider the name of the security provider for the given algorithm
     *
     * @throws NoSuchAlgorithmException if no security provider supports a {@code MacSpi} implementation for the
     * specified algorithm
     *
     * @see Mac#getInstance(String, String)
     */
    public HKDF(final String algorithm, final String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {

        this.hmacSupplier = buildHmacSupplier(() -> Mac.getInstance(algorithm, provider));
        this.defaultSalt = buildDefaultSalt(hmacSupplier.get());
    }

    /**
     * Constructs a new HKDF instance using the given HMAC algorithm as implemented by the given security provider.
     *
     * @param algorithm the name of the HMAC algorithm to use in the newly-constructed HKDF instance
     * @param provider the security provider that implements the given algorithm
     *
     * @throws NoSuchAlgorithmException if no security provider supports a {@code MacSpi} implementation for the
     * specified algorithm
     *
     * @see Mac#getInstance(String, Provider)
     */
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

    /**
     * Constructs a new HKDF instance using HmacSHA1 as its HMAC algorithm.
     *
     * @return a new HKDF instance using HmacSHA1 as its HMAC algorithm
     */
    public static HKDF withHmacSha1() {
        try {
            return new HKDF("HmacSHA1");
        } catch (final NoSuchAlgorithmException e) {
            throw new AssertionError("All Java implementations are required to support HmacSHA1");
        }
    }

    /**
     * Constructs a new HKDF instance using HmacSHA256 as its HMAC algorithm.
     *
     * @return a new HKDF instance using HmacSHA256 as its HMAC algorithm
     */
    public static HKDF withHmacSha256() {
        try {
            return new HKDF("HmacSHA256");
        } catch (final NoSuchAlgorithmException e) {
            throw new AssertionError("All Java implementations are required to support HmacSHA256");
        }
    }

    /**
     * Returns the name of the HMAC algorithm used by this HKDF instance.
     *
     * @return the name of the HMAC algorithm used by this HKDF instance
     */
    public String getAlgorithm() {
        return hmacSupplier.get().getAlgorithm();
    }

    /**
     * Derives key material from the given input key material, salt, and info. In the terminology of the HKDF
     * specification, this method combines the "expand" and "extract" steps of the HKDF algorithm.
     *
     * @param inputKeyMaterial the input key material from which to derive a key
     * @param salt optional salt value (a non-secret random value); may be {@code null} or empty
     *             // TODO Null info tests
     * @param info optional context and application specific information; may be {@code null}
     * @param outputKeyLength the desired length of the output key; must be less than or equal to 255 * (the output
     *                        length of this instance's HMAC function)
     *
     * @return the derived key material
     *
     * @see Mac#getMacLength()
     */
    public byte[] deriveKey(final byte[] inputKeyMaterial,
                            final byte[] salt,
                            final byte[] info,
                            final int outputKeyLength) {

        final Mac hmac = hmacSupplier.get();
        final Key pseudoRandomKey =
            new SecretKeySpec(extractPseudoRandomKey(inputKeyMaterial, salt, hmac), hmac.getAlgorithm());

        return deriveKey(pseudoRandomKey, info, outputKeyLength, hmac);
    }

    /**
     * Derives key material from the given pseudo-random key
     * @param pseudoRandomKey
     * @param info
     * @param outputKeyLength
     * @return
     */
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

    public byte[] extractPseudoRandomKey(final byte[] inputKeyMaterial, final byte[] salt) {
        return extractPseudoRandomKey(inputKeyMaterial, salt, hmacSupplier.get());
    }

    private byte[] extractPseudoRandomKey(final byte[] inputKeyMaterial, final byte[] salt, final Mac hmac) {
        try {
            hmac.init(salt != null && salt.length != 0 ? new SecretKeySpec(salt, hmac.getAlgorithm()) : defaultSalt);
            return hmac.doFinal(inputKeyMaterial);
        } catch (final InvalidKeyException e) {
            // Practically, this should never happen for any hashing algorithm (barring zero-length input key material)
            throw new IllegalArgumentException(e);
        }
    }
}
