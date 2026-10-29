package org.shalim.crypto;

import java.util.ArrayList;
import java.util.List;

/**
 * Merkle tree hashing and inclusion proofs as specified for Certificate
 * Transparency v2 (RFC 9162 §2.1). Leaves and interior nodes are hashed with
 * different prefixes (0x00 and 0x01), so a leaf can never be passed off as an
 * interior node.
 *
 * <p>Leaf <em>data</em> here is whatever the caller commits to. For the
 * censor decision log, that is each leaf's own record hash.
 */
public final class Merkle {

    private static final byte[] LEAF_PREFIX = {0x00};
    private static final byte[] NODE_PREFIX = {0x01};

    private Merkle() {
    }

    public static byte[] leafHash(byte[] leafData) {
        return Hashing.sha256(LEAF_PREFIX, leafData);
    }

    static byte[] nodeHash(byte[] left, byte[] right) {
        return Hashing.sha256(NODE_PREFIX, left, right);
    }

    /** MTH(D[n]). The root of an empty tree is SHA-256 of the empty string. */
    public static byte[] root(List<byte[]> leafData) {
        if (leafData.isEmpty()) {
            return Hashing.sha256(new byte[0]);
        }
        List<byte[]> hashes = new ArrayList<>(leafData.size());
        for (byte[] data : leafData) {
            hashes.add(leafHash(data));
        }
        return subtreeRoot(hashes, 0, hashes.size());
    }

    /** PATH(m, D[n]): sibling hashes from leaf {@code index} up to the root. */
    public static List<byte[]> inclusionPath(List<byte[]> leafData, int index) {
        if (index < 0 || index >= leafData.size()) {
            throw new IndexOutOfBoundsException("leaf " + index + " of " + leafData.size());
        }
        List<byte[]> hashes = new ArrayList<>(leafData.size());
        for (byte[] data : leafData) {
            hashes.add(leafHash(data));
        }
        List<byte[]> path = new ArrayList<>();
        path(hashes, index, 0, hashes.size(), path);
        return path;
    }

    /** RFC 9162 §2.1.3.2. False for any malformed input. */
    public static boolean verifyInclusion(byte[] leafData, long index, long treeSize,
                                          List<byte[]> path, byte[] expectedRoot) {
        if (leafData == null || path == null || expectedRoot == null
                || index < 0 || index >= treeSize) {
            return false;
        }
        long fn = index;
        long sn = treeSize - 1;
        byte[] r = leafHash(leafData);
        for (byte[] p : path) {
            if (p == null || sn == 0) {
                return false;
            }
            if ((fn & 1) == 1 || fn == sn) {
                r = nodeHash(p, r);
                if ((fn & 1) == 0) {
                    while ((fn & 1) == 0 && fn != 0) {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                r = nodeHash(r, p);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && Bytes.equal(r, expectedRoot);
    }

    private static byte[] subtreeRoot(List<byte[]> hashes, int from, int to) {
        int n = to - from;
        if (n == 1) {
            return hashes.get(from);
        }
        int k = largestPowerOfTwoBelow(n);
        return nodeHash(subtreeRoot(hashes, from, from + k), subtreeRoot(hashes, from + k, to));
    }

    private static void path(List<byte[]> hashes, int m, int from, int to, List<byte[]> out) {
        int n = to - from;
        if (n == 1) {
            return;
        }
        int k = largestPowerOfTwoBelow(n);
        if (m < k) {
            path(hashes, m, from, from + k, out);
            out.add(subtreeRoot(hashes, from + k, to));
        } else {
            path(hashes, m - k, from + k, to, out);
            out.add(subtreeRoot(hashes, from, from + k));
        }
    }

    /** Largest power of two strictly less than n, for n > 1. */
    private static int largestPowerOfTwoBelow(int n) {
        return Integer.highestOneBit(n - 1);
    }
}
