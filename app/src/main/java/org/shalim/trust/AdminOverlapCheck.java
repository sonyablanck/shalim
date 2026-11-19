package org.shalim.trust;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;

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
 * them.
 *
 * <h2>What replaces it</h2>
 *
 * <p>Private set intersection <em>cardinality</em> (PSI-CA), the
 * Diffie–Hellman construction: each side raises hashed elements to a secret
 * exponent, they exchange and double-blind, and the target learns only how
 * many elements match, never which. The authenticating hub learns nothing.
 *
 * <p>Implemented on the JDK in the prime-order subgroup of the RFC 3526
 * 2048-bit MODP group (a safe prime; elements are hashed and squared into the
 * quadratic residues, where DDH is believed hard). Admin sets are a handful of
 * keys, so the cost of 2048-bit exponentiation does not matter. No external
 * library is involved, so this is real code rather than a seam.
 *
 * <p>A target that dishonestly inputs all its members instead of its admins
 * learns only a count, at least one, which it knows anyway, and then refuses
 * the link on a false SHARED_ADMIN, which is its own loss.
 */
public final class AdminOverlapCheck {

    /** RFC 3526 group 14. */
    static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    static final BigInteger Q = P.shiftRight(1);
    private static final int ELEMENT_BYTES = 256;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AdminOverlapCheck() {
    }

    /** A fresh secret exponent for one run of the check. Never reused. */
    public static byte[] newExponent() {
        BigInteger e;
        do {
            e = new BigInteger(1, Bytes.random(40)).mod(Q);
        } while (e.signum() == 0);
        return e.toByteArray();
    }

    /** Either hub: blinds its own admin key fingerprints with a fresh secret exponent, shuffled. */
    public static List<byte[]> blindOwnAdmins(List<String> adminKeyFingerprints, byte[] secretExponent) {
        BigInteger e = exponent(secretExponent);
        List<byte[]> out = new ArrayList<>();
        for (String k : adminKeyFingerprints) {
            out.add(encode(hashToGroup(k).modPow(e, P)));
        }
        Collections.shuffle(out, RANDOM);
        return out;
    }

    /** Either hub: raises the other side's blinded set to its own exponent, shuffled. */
    public static List<byte[]> doubleBlind(List<byte[]> peerBlinded, byte[] secretExponent) {
        BigInteger e = exponent(secretExponent);
        List<byte[]> out = new ArrayList<>();
        for (byte[] b : peerBlinded) {
            BigInteger v = new BigInteger(1, b);
            if (!inGroup(v)) {
                throw new IllegalArgumentException("element is not in the group");
            }
            out.add(encode(v.modPow(e, P)));
        }
        Collections.shuffle(out, RANDOM);
        return out;
    }

    /** Target hub: size of the intersection, and nothing else. */
    public static int intersectionSize(List<byte[]> ownDoubleBlinded, List<byte[]> peerDoubleBlinded) {
        Set<String> mine = new HashSet<>();
        for (byte[] b : ownDoubleBlinded) {
            mine.add(Bytes.hex(b));
        }
        Set<String> counted = new HashSet<>();
        for (byte[] b : peerDoubleBlinded) {
            String h = Bytes.hex(b);
            if (mine.contains(h)) {
                counted.add(h);
            }
        }
        return counted.size();
    }

    static BigInteger hashToGroup(String element) {
        byte[] wide = new byte[ELEMENT_BYTES + 16];
        int pos = 0;
        for (int counter = 0; pos < wide.length; counter++) {
            byte[] block = Canonical.of("shalim.psi.h2g.v1").string(element).u64(counter).digest();
            int n = Math.min(block.length, wide.length - pos);
            System.arraycopy(block, 0, wide, pos, n);
            pos += n;
        }
        BigInteger h = new BigInteger(1, wide).mod(P);
        if (h.signum() == 0) {
            h = BigInteger.TWO;
        }
        return h.modPow(BigInteger.TWO, P); // into the order-Q subgroup of quadratic residues
    }

    private static boolean inGroup(BigInteger v) {
        return v.signum() > 0 && v.compareTo(P) < 0 && !v.equals(BigInteger.ONE) && v.modPow(Q, P).equals(BigInteger.ONE);
    }

    private static BigInteger exponent(byte[] secret) {
        BigInteger e = new BigInteger(1, secret).mod(Q);
        if (e.signum() == 0) {
            throw new IllegalArgumentException("zero exponent");
        }
        return e;
    }

    private static byte[] encode(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[ELEMENT_BYTES];
        int copy = Math.min(raw.length, ELEMENT_BYTES);
        System.arraycopy(raw, raw.length - copy, out, ELEMENT_BYTES - copy, copy);
        return out;
    }

}
