package org.shalim.crypto;

import java.util.ArrayList;
import java.util.List;
import org.shalim.testing.Check;

public final class MerkleTest {

    private MerkleTest() {
    }

    private static List<byte[]> leaves(int n) {
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(Canonical.of("leaf").u64(i).digest());
        }
        return out;
    }

    public static void testSmallTreesMatchTheDefinition() {
        List<byte[]> d = leaves(3);
        byte[] expected = Merkle.nodeHash(
                Merkle.nodeHash(Merkle.leafHash(d.get(0)), Merkle.leafHash(d.get(1))),
                Merkle.leafHash(d.get(2)));
        Check.equalBytes(expected, Merkle.root(d), "MTH of three leaves");
        Check.equalBytes(Merkle.leafHash(d.get(0)), Merkle.root(d.subList(0, 1)), "one leaf");
        Check.equalBytes(Hashing.sha256(new byte[0]), Merkle.root(new ArrayList<>()), "empty tree");
    }

    public static void testEveryInclusionProofVerifiesForSizesUpTo70() {
        for (int n = 1; n <= 70; n++) {
            List<byte[]> d = leaves(n);
            byte[] root = Merkle.root(d);
            for (int m = 0; m < n; m++) {
                List<byte[]> path = Merkle.inclusionPath(d, m);
                Check.isTrue(Merkle.verifyInclusion(d.get(m), m, n, path, root),
                        "leaf " + m + " of " + n);
                if (n > 1) {
                    int other = (m + 1) % n;
                    Check.isFalse(Merkle.verifyInclusion(d.get(m), other, n, path, root),
                            "wrong index " + other + " of " + n);
                    Check.isFalse(Merkle.verifyInclusion(d.get(other), m, n, path, root),
                            "wrong leaf at " + m + " of " + n);
                }
            }
        }
    }

    public static void testProofRejectsWrongRootSizeAndTruncation() {
        List<byte[]> d = leaves(32);
        byte[] root = Merkle.root(d);
        List<byte[]> path = Merkle.inclusionPath(d, 9);
        Check.isFalse(Merkle.verifyInclusion(d.get(9), 9, 32, path, Merkle.root(leaves(31))), "wrong root");
        Check.isFalse(Merkle.verifyInclusion(d.get(9), 9, 33, path, root), "wrong size");
        Check.isFalse(Merkle.verifyInclusion(d.get(9), 9, 32, path.subList(0, path.size() - 1), root),
                "truncated path");
        Check.isFalse(Merkle.verifyInclusion(d.get(9), 40, 32, path, root), "index past the end");
    }
}
