package org.shalim.crypto;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Shamir secret sharing over GF(2^8) (the AES field, polynomial 0x11b). Each
 * byte of the secret is shared separately, with its own random polynomial of
 * degree {@code threshold - 1}. Any {@code threshold} shares rebuild the
 * secret. Fewer reveal nothing about it.
 *
 * <p>This is for {@code RegisteredUser.enrolRecoveryShares}. Plain Shamir has
 * no integrity: a wrong or tampered share rebuilds a wrong secret without any
 * error. Callers must check the result, for example by confirming that the
 * rebuilt seed derives the expected public key. Field arithmetic here uses no
 * lookup tables and no secret-dependent branches.
 */
public final class Shamir {

    /** One share: its x-coordinate (1..255) and one y-byte per secret byte. */
    public record Share(int x, byte[] y) {
        public Share {
            if (x < 1 || x > 255) {
                throw new IllegalArgumentException("share x must be in 1..255");
            }
            y = y.clone();
        }

        @Override
        public byte[] y() {
            return y.clone();
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private Shamir() {
    }

    public static List<Share> split(byte[] secret, int threshold, int shares) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("nothing to share");
        }
        if (threshold < 2 || threshold > shares || shares > 255) {
            throw new IllegalArgumentException("need 2 <= threshold <= shares <= 255");
        }
        byte[][] ys = new byte[shares][secret.length];
        byte[] coefficients = new byte[threshold];
        for (int b = 0; b < secret.length; b++) {
            coefficients[0] = secret[b];
            byte[] random = new byte[threshold - 1];
            RANDOM.nextBytes(random);
            System.arraycopy(random, 0, coefficients, 1, threshold - 1);
            for (int s = 0; s < shares; s++) {
                ys[s][b] = (byte) evaluate(coefficients, s + 1);
            }
        }
        Bytes.wipe(coefficients);
        List<Share> out = new ArrayList<>(shares);
        for (int s = 0; s < shares; s++) {
            out.add(new Share(s + 1, ys[s]));
            Bytes.wipe(ys[s]);
        }
        return out;
    }

    /** Lagrange interpolation at x = 0. Needs at least threshold distinct shares. */
    public static byte[] combine(List<Share> shares) {
        if (shares == null || shares.size() < 2) {
            throw new IllegalArgumentException("need at least two shares");
        }
        int length = shares.get(0).y().length;
        Set<Integer> xs = new HashSet<>();
        for (Share share : shares) {
            if (!xs.add(share.x()) || share.y().length != length) {
                throw new IllegalArgumentException("shares must be distinct and the same length");
            }
        }
        byte[] secret = new byte[length];
        for (int i = 0; i < shares.size(); i++) {
            int xi = shares.get(i).x();
            // basis_i(0) = prod_{j != i} x_j / (x_j - x_i); subtraction is XOR in GF(2^8).
            int basis = 1;
            for (int j = 0; j < shares.size(); j++) {
                if (j != i) {
                    int xj = shares.get(j).x();
                    basis = mul(basis, mul(xj, inverse(xj ^ xi)));
                }
            }
            byte[] yi = shares.get(i).y();
            for (int b = 0; b < length; b++) {
                secret[b] ^= (byte) mul(yi[b] & 0xff, basis);
            }
        }
        return secret;
    }

    private static int evaluate(byte[] coefficients, int x) {
        int result = 0;
        for (int i = coefficients.length - 1; i >= 0; i--) {
            result = mul(result, x) ^ (coefficients[i] & 0xff);
        }
        return result;
    }

    /** Carry-less multiply mod 0x11b, branch-free on its inputs. */
    static int mul(int a, int b) {
        int product = 0;
        for (int i = 0; i < 8; i++) {
            product ^= -(b & 1) & a;
            int carry = -((a >> 7) & 1) & 0x1b;
            a = ((a << 1) ^ carry) & 0xff;
            b >>= 1;
        }
        return product;
    }

    /** a^254 = a^-1 in GF(2^8). */
    static int inverse(int a) {
        int result = 1;
        int base = a;
        int exponent = 254;
        for (int i = 0; i < 8; i++) {
            int factor = mul(result, base);
            int take = -(exponent & 1);
            result = (factor & take) | (result & ~take);
            base = mul(base, base);
            exponent >>= 1;
        }
        return result;
    }
}
