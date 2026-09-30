package org.shalim.trust;

import java.util.List;

/**
 * The "no shared admins" check, rebuilt so it no longer names the prober.
 *
 * <h2>What was wrong with salted hashes</h2>
 *
 * <p>The earlier check had the authenticating hub send salted hashes of its
 * admins' keys, and the target compare them with its own admins' hashes under
 * the same salt. But nothing stopped the target hashing <em>every member's</em>
 * key with that salt. The prober is by definition an admin of the
 * authenticating hub and a member of the target, so the intersection named
 * them. Anonymous eligibility is pointless if this check leaks the identity
 * straight back.
 *
 * <h2>What replaces it</h2>
 *
 * <p>Private set intersection <em>cardinality</em> (PSI-CA) over the two admin
 * key sets, e.g. the Diffie–Hellman construction: each side blinds its set
 * with a secret exponent, they exchange and double-blind, and the target
 * learns only how many elements match, never which. The authenticating hub
 * learns nothing.
 *
 * <p>A target that dishonestly inputs all its members instead of its admins
 * learns only a count of the authenticating hub's admins who are members
 * there — at least one, which it knows anyway — and then refuses the link on
 * a false SHARED_ADMIN, which is its own loss. It cannot learn who.
 */
public class AdminOverlapCheck {

    private AdminOverlapCheck() {
    }

    /** Authenticating hub: blind own admin keys with a fresh secret exponent. */
    public static List<byte[]> blindOwnAdmins(List<byte[]> adminKeys, byte[] secretExponent) {
        // PSEUDO-CODE
        // RETURN shuffle([ hashToGroup(k) ^ secretExponent FOR k IN adminKeys ])
        return null;
    }

    /** Target hub: double-blind the peer's set and blind its own. */
    public static List<byte[]> doubleBlind(List<byte[]> peerBlinded, byte[] secretExponent) {
        // PSEUDO-CODE
        // RETURN shuffle([ e ^ secretExponent FOR e IN peerBlinded ])
        return null;
    }

    /** Target hub: size of the intersection, and nothing else. */
    public static int intersectionSize(List<byte[]> ownDoubleBlinded, List<byte[]> peerDoubleBlinded) {
        // PSEUDO-CODE
        // RETURN |set(ownDoubleBlinded) ∩ set(peerDoubleBlinded)|
        //    // Both lists shuffled before exchange, so position reveals nothing.
        return 0;
    }
}
