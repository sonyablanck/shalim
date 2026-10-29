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
        // TODO: pseudo-code
    }

    /**
     * Forms or renews a bond when both directions count. Requires a live
     * exchange between the two hubs, over the admins' memberships.
     */
    public static AuthBond formIfMutual(AuthLink aToB, AuthLink bToA, Instant now) {
        // PSEUDO-CODE
        // IF aToB == null OR bToA == null -> RETURN null
        // IF NOT aToB.counts(now) OR NOT bToA.counts(now) -> RETURN null
        // bond = new AuthBond(A, B, expiresAt = now + bondTtl)
        // each side signs; RETURN bond
        // On first formation, each side also witnesses the other's network
        // claim: signs (claimId, claimedAt), never the BSSIDs. This is the
        // evidence of age NetworkClaim.older reads in a dispute.
        return null;
    }

    public boolean isCurrent(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    /** The anonymised form published on the card. Built by the subject hub. */
    public BondProof toProof(java.util.List<byte[]> ringOfListedIssuerKeys, byte[] ownPrivateKey) {
        // TODO: pseudo-code
        return null;
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
