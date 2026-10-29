/**
 * Cryptographic primitives every other package builds on. Implemented on the
 * JDK's own providers only (Java 17+), so there is still nothing to depend on.
 *
 * <h2>Choices</h2>
 * <ul>
 *   <li><b>Hash:</b> SHA-256. Every hash that commits to structured data goes
 *       through {@link org.shalim.crypto.Canonical}, which starts with a
 *       versioned domain tag and length-prefixes every field, so two different
 *       records can never encode to the same bytes and a hash made for one
 *       purpose cannot be replayed as another.</li>
 *   <li><b>Signatures:</b> Ed25519 ({@link org.shalim.crypto.Ed25519}). Keys
 *       travel as 32 raw bytes and are named by
 *       {@link org.shalim.crypto.Fingerprints}.</li>
 *   <li><b>Encryption to a key:</b> X25519 + HKDF-SHA256 + ChaCha20-Poly1305
 *       ({@link org.shalim.crypto.SealedBox}), in the shape of HPKE base mode.
 *       It is not wire-compatible with RFC 9180.</li>
 *   <li><b>Encryption at rest:</b> ChaCha20-Poly1305 with a random 96-bit nonce
 *       ({@link org.shalim.crypto.Aead}).</li>
 *   <li><b>PRF and sampling:</b> HMAC-SHA256 ({@link org.shalim.crypto.Prf}),
 *       with rejection sampling so sampled indices are unbiased.</li>
 *   <li><b>Commit-then-reveal nonces:</b> a hash chain
 *       ({@link org.shalim.crypto.HashChain}). Each revealed value is checkable
 *       against the commitment and does not give away the next one.</li>
 *   <li><b>Transparency trees:</b> RFC 9162 (Certificate Transparency v2)
 *       Merkle hashing and inclusion proofs ({@link org.shalim.crypto.Merkle}).</li>
 *   <li><b>Recovery shares:</b> Shamir secret sharing over GF(2^8)
 *       ({@link org.shalim.crypto.Shamir}).</li>
 * </ul>
 *
 * <h2>Deliberately not here</h2>
 *
 * <p>BBS anonymous credentials, RLN-style nullifiers, PSI-cardinality and
 * linkable ring signatures. Those schemes have not been chosen yet (README
 * open question 18). They are easy to get subtly wrong, and the plan is to bind
 * audited Rust or Go implementations over JNI rather than write them by hand.
 *
 * <h2>Android</h2>
 *
 * <p>Ed25519 and X25519 through JCA are only present on recent Android
 * releases. The Android build will need a provider (Tink or BouncyCastle)
 * behind these same classes, and account keys behind a hardware-backed
 * {@link org.shalim.crypto.AccountKeyStore}. Android Keystore only supports
 * Ed25519 on recent releases, so the account-key algorithm may need to be
 * ECDSA P-256 there. That decision is still open.
 */
package org.shalim.crypto;
