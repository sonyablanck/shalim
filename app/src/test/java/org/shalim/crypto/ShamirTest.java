package org.shalim.crypto;

import java.util.ArrayList;
import java.util.List;
import org.shalim.testing.Check;

public final class ShamirTest {

    private ShamirTest() {
    }

    public static void testFieldInverse() {
        for (int a = 1; a < 256; a++) {
            Check.equal(1, Shamir.mul(a, Shamir.inverse(a)), "a * a^-1 for a = " + a);
        }
        Check.equal(0xc1, Shamir.mul(0x57, 0x83), "FIPS-197 §4.2 example");
    }

    public static void testAnyThresholdSubsetRebuildsTheSecret() {
        byte[] secret = Bytes.random(32);
        List<Shamir.Share> shares = Shamir.split(secret, 3, 5);
        for (int i = 0; i < 5; i++) {
            for (int j = i + 1; j < 5; j++) {
                for (int k = j + 1; k < 5; k++) {
                    List<Shamir.Share> subset = List.of(shares.get(i), shares.get(j), shares.get(k));
                    Check.equalBytes(secret, Shamir.combine(subset), "shares " + i + j + k);
                }
            }
        }
        Check.equalBytes(secret, Shamir.combine(shares), "all five");
    }

    public static void testBelowThresholdDoesNotRebuild() {
        byte[] secret = Bytes.random(32);
        List<Shamir.Share> shares = Shamir.split(secret, 3, 5);
        Check.isFalse(Bytes.equal(secret, Shamir.combine(shares.subList(0, 2))), "two of three");
    }

    public static void testRejectsBadParameters() {
        Check.throwsA(IllegalArgumentException.class, () -> Shamir.split(new byte[4], 1, 3), "threshold 1");
        Check.throwsA(IllegalArgumentException.class, () -> Shamir.split(new byte[4], 4, 3), "threshold > n");
        List<Shamir.Share> dup = new ArrayList<>(Shamir.split(new byte[4], 2, 3).subList(0, 1));
        dup.add(dup.get(0));
        Check.throwsA(IllegalArgumentException.class, () -> Shamir.combine(dup), "duplicate x");
    }
}
