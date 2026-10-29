package org.shalim.hub;

import java.util.Locale;
import java.util.regex.Pattern;

/** Parsing and classifying access-point hardware addresses. */
public final class Bssid {

    private static final Pattern FORM = Pattern.compile("([0-9a-f]{2}:){5}[0-9a-f]{2}");

    private Bssid() {
    }

    /** Lower case, colon-separated. Null if it is not a MAC address. */
    public static String normalise(String bssid) {
        if (bssid == null) {
            return null;
        }
        String n = bssid.trim().toLowerCase(Locale.ROOT).replace('-', ':');
        return FORM.matcher(n).matches() ? n : null;
    }

    /**
     * Whether an access point can hold a claim. Refused if:
     * <ul>
     *   <li>it is malformed;</li>
     *   <li>it is all zeros or all ones;</li>
     *   <li>the multicast bit is set;</li>
     *   <li>the locally-administered bit is set. Phone hotspots and many
     *       mesh systems randomise their address per session, so a claim on
     *       one would lapse the next time the hotspot came up, and anyone
     *       could pick that address for their own hotspot.</li>
     * </ul>
     */
    public static boolean isStable(String bssid) {
        String n = normalise(bssid);
        if (n == null || n.equals("00:00:00:00:00:00") || n.equals("ff:ff:ff:ff:ff:ff")) {
            return false;
        }
        int first = Integer.parseInt(n.substring(0, 2), 16);
        boolean multicast = (first & 0x01) != 0;
        boolean locallyAdministered = (first & 0x02) != 0;
        return !multicast && !locallyAdministered;
    }
}
