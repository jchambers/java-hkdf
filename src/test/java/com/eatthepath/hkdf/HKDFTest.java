package com.eatthepath.hkdf;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class HKDFTest {

    @Test
    void withHmacSha1() {
        assertEquals("HmacSHA1", HKDF.withHmacSha1().getAlgorithm());
    }

    @Test
    void withHmacSha256() {
        assertEquals("HmacSHA256", HKDF.withHmacSha256().getAlgorithm());
    }

    @ParameterizedTest
    @MethodSource
    void extractPseudoRandomKey(final String algorithm,
                                final byte[] inputKeyMaterial,
                                final byte[] salt,
                                final byte[] expectedKey) throws NoSuchAlgorithmException {

        assertArrayEquals(expectedKey,
                new HKDF(algorithm).extractPseudoRandomKey(inputKeyMaterial, salt));
    }

    private static Stream<Arguments> extractPseudoRandomKey() {
        // Test vectors from https://www.rfc-editor.org/rfc/rfc5869.txt, Appendix A
        return Stream.of(
                Arguments.of(
                        "HmacSHA256",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        parseHex("000102030405060708090a0b0c"),
                        parseHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
                        parseHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                        parseHex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        new byte[0],
                        parseHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b"),
                        parseHex("000102030405060708090a0b0c"),
                        parseHex("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
                        parseHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                        parseHex("8adae09a2a307059478d309b26c4115a224cfaf6")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        new byte[0],
                        parseHex("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
                        null,
                        parseHex("2adccada18779e7c2077ad2eb19d3f3e731385dd")
                )
        );
    }

    @Test
    void extractPseudoRandomKeyNullInputs() {
        assertDoesNotThrow(() -> HKDF.withHmacSha256().extractPseudoRandomKey(null, null));
    }

    @ParameterizedTest
    @MethodSource
    void deriveKey(final String algorithm,
                   final byte[] inputKeyMaterial,
                   final byte[] salt,
                   final byte[] info,
                   final int outputKeyLength,
                   final byte[] expectedKey) throws NoSuchAlgorithmException {

        assertArrayEquals(expectedKey, new HKDF(algorithm).deriveKey(inputKeyMaterial, salt, info, outputKeyLength));
    }

    private static Stream<Arguments> deriveKey() {
        // Test vectors from https://www.rfc-editor.org/rfc/rfc5869.txt, Appendix A
        return Stream.of(
                Arguments.of(
                        "HmacSHA256",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        parseHex("000102030405060708090a0b0c"),
                        parseHex("f0f1f2f3f4f5f6f7f8f9"),
                        42,
                        parseHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
                        parseHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                        parseHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                        82,
                        parseHex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        new byte[0],
                        new byte[0],
                        42,
                        parseHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        new byte[0],
                        null,
                        42,
                        parseHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        null,
                        null,
                        42,
                        parseHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b"),
                        parseHex("000102030405060708090a0b0c"),
                        parseHex("f0f1f2f3f4f5f6f7f8f9"),
                        42,
                        parseHex("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
                        parseHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                        parseHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                        82,
                        parseHex("0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                        new byte[0],
                        new byte[0],
                        42,
                        parseHex("0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
                        null,
                        new byte[0],
                        42,
                        parseHex("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
                        null,
                        null,
                        42,
                        parseHex("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48")
                )
        );
    }

    @ParameterizedTest
    @MethodSource
    void deriveKeyFromPseudoRandomKey(final String algorithm,
                                      final byte[] pseudoRandomKey,
                                      final byte[] info,
                                      final int outputKeyLength,
                                      final byte[] expectedKey) throws NoSuchAlgorithmException {

        assertArrayEquals(expectedKey, new HKDF(algorithm).deriveKey(pseudoRandomKey, info, outputKeyLength));
    }

    private static Stream<Arguments> deriveKeyFromPseudoRandomKey() {
        // Test vectors from https://www.rfc-editor.org/rfc/rfc5869.txt, Appendix A
        return Stream.of(
                Arguments.of(
                        "HmacSHA256",
                        parseHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
                        parseHex("f0f1f2f3f4f5f6f7f8f9"),
                        42,
                        parseHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
                        parseHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                        82,
                        parseHex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
                        new byte[0],
                        42,
                        parseHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
                ),

                Arguments.of(
                        "HmacSHA256",
                        parseHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
                        null,
                        42,
                        parseHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"),
                        parseHex("f0f1f2f3f4f5f6f7f8f9"),
                        42,
                        parseHex("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("8adae09a2a307059478d309b26c4115a224cfaf6"),
                        parseHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                        82,
                        parseHex("0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01"),
                        new byte[0],
                        42,
                        parseHex("0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01"),
                        null,
                        42,
                        parseHex("0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("2adccada18779e7c2077ad2eb19d3f3e731385dd"),
                        new byte[0],
                        42,
                        parseHex("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48")
                ),

                Arguments.of(
                        "HmacSHA1",
                        parseHex("2adccada18779e7c2077ad2eb19d3f3e731385dd"),
                        null,
                        42,
                        parseHex("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48")
                )
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {"HmacSHA1", "HmacSHA256"})
    void deriveKeyFromPseudoRandomKeyShortKey(final String algorithm) throws NoSuchAlgorithmException {
        final HKDF hkdf = new HKDF(algorithm);

        assertThrows(IllegalArgumentException.class, () -> hkdf.deriveKey(null, null, 32));
        assertThrows(IllegalArgumentException.class, () -> hkdf.deriveKey(new byte[0], null, 32));
    }

    @ParameterizedTest
    @ValueSource(strings = {"HmacSHA1", "HmacSHA256"})
    void deriveKeyLengthBounds(final String algorithm) throws NoSuchAlgorithmException {
        final HKDF hkdf = new HKDF(algorithm);

        final byte[] inputKeyMaterial = parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        final byte[] salt = parseHex("000102030405060708090a0b0c");
        final byte[] info = parseHex("f0f1f2f3f4f5f6f7f8f9");

        assertThrows(IllegalArgumentException.class, () -> hkdf.deriveKey(inputKeyMaterial, salt, info, 0));

        final int maxOutputKeyLength;
        {
            final Mac hmac = Mac.getInstance(algorithm);
            maxOutputKeyLength = hmac.getMacLength() * 255;
        }

        assertDoesNotThrow(() -> hkdf.deriveKey(inputKeyMaterial, salt, info, maxOutputKeyLength));

        assertThrows(IllegalArgumentException.class,
                () -> hkdf.deriveKey(inputKeyMaterial, salt, info, maxOutputKeyLength + 1));
    }

  private static byte[] parseHex(final CharSequence charSequence) {
    if (charSequence == null) {
      return new byte[0];
    }

    if (charSequence.length() % 2 != 0) {
      throw new IllegalArgumentException("Character sequence must have an even number of characters");
    }

    final byte[] parsed = new byte[charSequence.length() / 2];

    for (int i = 0; i < charSequence.length(); i += 2) {
      parsed[i / 2] = (byte) (Character.digit(charSequence.charAt(i), 16) << 4 |
          Character.digit(charSequence.charAt(i + 1), 16));
    }

    return parsed;
  }
}
