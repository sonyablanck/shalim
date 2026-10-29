package org.shalim.crypto;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import org.shalim.testing.Check;

/** Published test vectors first, then properties. */
public final class CryptoPrimitivesTest {

    private CryptoPrimitivesTest() {
    }

    // --- published vectors ---------------------------------------------------

    public static void testSha256Abc() {
        Check.equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Hashing.sha256Hex("abc"), "FIPS 180-2 'abc'");
    }

    public static void testHmacRfc4231Case1() {
        byte[] key = new byte[20];
        java.util.Arrays.fill(key, (byte) 0x0b);
        Check.equal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                Bytes.hex(Prf.hmac(key, "Hi There".getBytes(StandardCharsets.US_ASCII))),
                "RFC 4231 test case 1");
    }

    public static void testHkdfRfc5869Case1() {
        byte[] ikm = new byte[22];
        java.util.Arrays.fill(ikm, (byte) 0x0b);
        byte[] salt = Bytes.fromHex("000102030405060708090a0b0c");
        byte[] info = Bytes.fromHex("f0f1f2f3f4f5f6f7f8f9");
        Check.equal("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                Bytes.hex(Hkdf.extract(salt, ikm)), "RFC 5869 PRK");
        Check.equal("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865",
                Bytes.hex(Hkdf.derive(salt, ikm, info, 42)), "RFC 5869 OKM");
    }

    public static void testEd25519Rfc8032Test1() {
        SoftwareSigner signer = SoftwareSigner.fromSeed(
                Bytes.fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        Check.equal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                Bytes.hex(signer.publicKey()), "RFC 8032 public key from seed");
        byte[] signature = signer.sign(new byte[0]);
        Check.equal("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                        + "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                Bytes.hex(signature), "RFC 8032 signature of the empty message");
        Check.isTrue(Ed25519.verify(signer.publicKey(), new byte[0], signature), "verifies");
    }

    public static void testX25519Rfc7748() {
        EncryptionKeyPair alice = EncryptionKeyPair.fromPrivate(
                Bytes.fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        EncryptionKeyPair bob = EncryptionKeyPair.fromPrivate(
                Bytes.fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
        Check.equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                Bytes.hex(alice.publicKey()), "Alice public");
        Check.equal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                Bytes.hex(bob.publicKey()), "Bob public");
        String shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        Check.equal(shared, Bytes.hex(alice.agree(bob.publicKey())), "Alice's shared secret");
        Check.equal(shared, Bytes.hex(bob.agree(alice.publicKey())), "Bob's shared secret");
    }

    public static void testX25519RejectsLowOrderPoint() {
        EncryptionKeyPair me = EncryptionKeyPair.generate();
        Check.throwsA(CryptoException.class, () -> me.agree(new byte[32]), "u = 0 refused");
    }

    // --- signatures ----------------------------------------------------------

    public static void testSignatureRejectsTamperingAndWrongKey() {
        SoftwareSigner a = SoftwareSigner.generate();
        SoftwareSigner b = SoftwareSigner.generate();
        byte[] message = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] signature = a.sign(message);
        Check.isTrue(Ed25519.verify(a.publicKey(), message, signature), "good signature");
        Check.isFalse(Ed25519.verify(b.publicKey(), message, signature), "wrong key");
        signature[0] ^= 1;
        Check.isFalse(Ed25519.verify(a.publicKey(), message, signature), "flipped bit");
        Check.isFalse(Ed25519.verify(a.publicKey(), message, new byte[3]), "short signature");
        Check.isFalse(Ed25519.verify(null, message, signature), "null key");
    }

    public static void testFingerprintsAreKindSeparated() {
        byte[] key = Bytes.random(32);
        Check.isFalse(Fingerprints.signingKey(key).equals(Fingerprints.encryptionKey(key)),
                "same bytes, different kinds, different fingerprints");
        SoftwareSigner signer = SoftwareSigner.generate();
        Check.isTrue(Fingerprints.matchesSigningKey(signer.fingerprint(), signer.publicKey()), "matches");
    }

    // --- canonical encoding --------------------------------------------------

    public static void testCanonicalIsUnambiguous() {
        byte[] ab = Canonical.of("t").string("ab").string("c").digest();
        byte[] a = Canonical.of("t").string("a").string("bc").digest();
        Check.isFalse(Bytes.equal(ab, a), "field boundaries count");
        byte[] nullField = Canonical.of("t").string(null).digest();
        byte[] empty = Canonical.of("t").string("").digest();
        Check.isFalse(Bytes.equal(nullField, empty), "null differs from empty");
        byte[] otherDomain = Canonical.of("u").string("ab").string("c").digest();
        Check.isFalse(Bytes.equal(ab, otherDomain), "domain tag counts");
        Check.isTrue(Bytes.equal(Canonical.of("t").strings(List.of("b", "a")).digest(),
                Canonical.of("t").strings(List.of("a", "b")).digest()), "sets are order-free");
        Check.isTrue(Bytes.equal(Canonical.of("t").hex("ABCD").digest(),
                Canonical.of("t").hex("abcd").digest()), "hex is case-free");
    }

    // --- encryption ----------------------------------------------------------

    public static void testAeadRoundTripAndBinding() {
        byte[] key = Aead.newKey();
        byte[] aad = "slot 7".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = Aead.seal(key, "secret".getBytes(StandardCharsets.UTF_8), aad);
        Check.equal("secret", new String(Aead.open(key, sealed, aad), StandardCharsets.UTF_8), "round trip");
        Check.throwsA(CryptoException.class,
                () -> Aead.open(key, sealed, "slot 8".getBytes(StandardCharsets.UTF_8)), "wrong AAD");
        Check.throwsA(CryptoException.class, () -> Aead.open(Aead.newKey(), sealed, aad), "wrong key");
        sealed[sealed.length - 1] ^= 1;
        Check.throwsA(CryptoException.class, () -> Aead.open(key, sealed, aad), "tampered");
    }

    public static void testSealedBoxRoundTripAndBinding() {
        EncryptionKeyPair auditor = EncryptionKeyPair.generate();
        EncryptionKeyPair other = EncryptionKeyPair.generate();
        byte[] aad = "leaf 3".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = SealedBox.seal(auditor.publicKey(), "question".getBytes(StandardCharsets.UTF_8), aad);
        Check.equal("question", new String(SealedBox.open(auditor, sealed, aad), StandardCharsets.UTF_8),
                "round trip");
        Check.throwsA(CryptoException.class, () -> SealedBox.open(other, sealed, aad), "other recipient");
        Check.throwsA(CryptoException.class,
                () -> SealedBox.open(auditor, sealed, "leaf 4".getBytes(StandardCharsets.UTF_8)), "wrong AAD");
        byte[] again = SealedBox.seal(auditor.publicKey(), "question".getBytes(StandardCharsets.UTF_8), aad);
        Check.isFalse(Bytes.equal(sealed, again), "fresh ephemeral key every time");
    }

    // --- sampling and hash chains -------------------------------------------

    public static void testSampleDistinctIsDeterministicDistinctAndInRange() {
        byte[] key = Bytes.random(32);
        byte[] input = "root".getBytes(StandardCharsets.UTF_8);
        List<Long> first = Prf.sampleDistinct(key, input, 20, 64);
        List<Long> second = Prf.sampleDistinct(key, input, 20, 64);
        Check.equal(first, second, "deterministic");
        Check.equal(20, new HashSet<>(first).size(), "distinct");
        for (long i : first) {
            Check.isTrue(i >= 0 && i < 64, "in range");
        }
        Check.isFalse(first.equals(Prf.sampleDistinct(Bytes.random(32), input, 20, 64)),
                "key changes the sample");
        Check.equal(5, Prf.sampleDistinct(key, input, 9, 5).size(), "count capped at bound");
    }

    public static void testSampleDistinctIsRoughlyUniform() {
        int bound = 8;
        int[] counts = new int[bound];
        byte[] key = Bytes.random(32);
        for (int trial = 0; trial < 4000; trial++) {
            for (long i : Prf.sampleDistinct(key, Canonical.of("t").u64(trial).encode(), 1, bound)) {
                counts[(int) i]++;
            }
        }
        for (int c : counts) {
            // Expected 500 each; a fair source stays well inside this band.
            Check.isTrue(c > 380 && c < 620, "bucket count " + c);
        }
    }

    public static void testHashChainRevealsVerifyAndDoNotLeakForward() {
        byte[] seed = Bytes.random(32);
        int length = 30;
        LocalDate start = LocalDate.of(2026, 10, 1);
        byte[] anchor = HashChain.anchor(seed, length);
        byte[] day5 = HashChain.reveal(seed, length, start, start.plusDays(5));
        byte[] day6 = HashChain.reveal(seed, length, start, start.plusDays(6));
        Check.isTrue(HashChain.verify(anchor, length, start, start.plusDays(5), day5), "day 5 verifies");
        Check.isTrue(HashChain.verify(anchor, length, start, start.plusDays(6), day6), "day 6 verifies");
        Check.isFalse(HashChain.verify(anchor, length, start, start.plusDays(6), day5),
                "a value only verifies for its own day");
        Check.isFalse(HashChain.verify(anchor, length, start, start.plusDays(5), Bytes.random(32)),
                "random value refused");
        Check.isNull(HashChain.reveal(seed, length, start, start), "day 0 is the anchor's, not a nonce");
        Check.isNull(HashChain.reveal(seed, length, start, start.plusDays(31)), "past the end");
    }
}
