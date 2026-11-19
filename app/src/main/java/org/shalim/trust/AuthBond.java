package org.shalim.trust;

import java.time.Instant;

/**
 * A mutual authentication: hub A currently authenticates hub B <em>and</em>
 * hub B currently authenticates hub A.
 *
 * <p>Bonds, not links, are what hub search counts. A hub that authenticates
 * others but is authenticated by nobody has zero bonds and does not appear in
 * search at any setting, because search refuses 0 as a threshold. The remedy
 * is a {@link ReciprocityInvite}: the admin asks the hub they authenticate to
 * authenticate them back.
 *
 * <p>A bond is co-signed by both hubs' issuer keys and expires quickly — a
 * few days — so it is re-signed as long as both links keep counting and simply
 * lapses when either stops. Nothing announces the lapse.
 *
 * <p>A bond is the first piece of trust state in Shalim that leaves a device.
 * It is published on the hub's card as a {@link BondProof}, which proves "one
 * of the listed hubs is bonded with this one" without saying which. See that
 * class for why, and for what it still leaks.
 */
public class AuthBond {

    private String bondId;

    /** Both issuer key fingerprints. Held privately by the two parties only. */
    private String keyFingerprintA;
    private String keyFingerprintB;

    private Instant formedAt;

    /** Short. Re-signed daily while both links count. */
    private Instant expiresAt;

    /** Each side's signature over (A, B, expiresAt). */
    private byte[] signatureA;
    private byte[] signatureB;

    public AuthBond() {
        this.bondId = org.shalim.crypto.Bytes.randomId();
    }

    /**
     * Forms or renews a bond when both directions count. Requires a live
     * exchange between the two hubs, over the admins' memberships.
     */
    /** Short: re-signed daily while both links count, and lapses silently when either stops. */
    public static final java.time.Duration TTL = java.time.Duration.ofDays(3);

    public static AuthBond formIfMutual(AuthLink aToB, AuthLink bToA, Instant now) {
        if (aToB == null || bToA == null || !aToB.counts(now) || !bToA.counts(now)
                || !aToB.getAuthenticatorKeyFingerprint().equals(bToA.getSubjectKeyFingerprint())
                || !aToB.getSubjectKeyFingerprint().equals(bToA.getAuthenticatorKeyFingerprint())) {
            return null;
        }
        AuthBond b = new AuthBond();
        // Ordered, so both sides build the same record.
        boolean aFirst = aToB.getAuthenticatorKeyFingerprint().compareTo(aToB.getSubjectKeyFingerprint()) < 0;
        b.keyFingerprintA = aFirst ? aToB.getAuthenticatorKeyFingerprint() : aToB.getSubjectKeyFingerprint();
        b.keyFingerprintB = aFirst ? aToB.getSubjectKeyFingerprint() : aToB.getAuthenticatorKeyFingerprint();
        b.formedAt = now;
        b.expiresAt = now.plus(TTL);
        // Each side then signs with signAs over a live exchange; witnessing
        // each other's network claim on first formation comes with bond
        // exchange in stage 5.
        return b;
    }

    public boolean isCurrent(Instant now) {
        return expiresAt != null && now.isBefore(expiresAt) && signatureA != null && signatureB != null;
    }

    /** The anonymised form published on the card. Built by the subject hub. */
    public BondProof toProof(java.util.List<byte[]> ringOfListedIssuerKeys, byte[] ownPrivateKey) {
        // Stage 5: a linkable ring signature over the listed issuer keys.
        return null;
    }

    byte[] payload() {
        return org.shalim.crypto.Canonical.of("shalim.bond.v1").hex(keyFingerprintA).hex(keyFingerprintB)
                .instant(expiresAt).encode();
    }

    /** One side's co-signature. Returns false if the signer is neither party. */
    public boolean signAs(org.shalim.crypto.Signer key) {
        String fp = key.fingerprint();
        if (fp.equals(keyFingerprintA)) {
            signatureA = key.sign(payload());
            return true;
        }
        if (fp.equals(keyFingerprintB)) {
            signatureB = key.sign(payload());
            return true;
        }
        return false;
    }

    public boolean verify(byte[] publicKeyA, byte[] publicKeyB) {
        return signatureA != null && signatureB != null
                && org.shalim.crypto.Ed25519.verify(publicKeyA, payload(), signatureA)
                && org.shalim.crypto.Ed25519.verify(publicKeyB, payload(), signatureB);
    }

    public String otherParty(String ownKeyFingerprint) {
        return ownKeyFingerprint.equals(keyFingerprintA) ? keyFingerprintB : keyFingerprintA;
    }

    // --- accessors --------------------------------------------------------

    public String getBondId() {
        return bondId;
    }

    public String getKeyFingerprintA() {
        return keyFingerprintA;
    }

    public String getKeyFingerprintB() {
        return keyFingerprintB;
    }

    public Instant getFormedAt() {
        return formedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
