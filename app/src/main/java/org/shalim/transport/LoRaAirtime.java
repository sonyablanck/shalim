package org.shalim.transport;

/**
 * Time on air of one LoRa frame, from the Semtech SX127x datasheet formula
 * (also AN1200.13), and the largest payload at each spreading factor in the
 * EU868 band.
 *
 * <pre>
 *   Tsym      = 2^SF / BW
 *   Tpreamble = (Npreamble + 4.25) · Tsym
 *   Npayload  = 8 + max(ceil((8·PL − 4·SF + 28 + 16·CRC − 20·IH) / (4·(SF − 2·DE))) · (CR + 4), 0)
 *   Tframe    = Tpreamble + Npayload · Tsym
 * </pre>
 * Explicit header (IH = 0), CRC on, and low-data-rate optimisation (DE) on
 * whenever a symbol lasts 16 ms or more. At SF7, 125 kHz, CR 4/5, an 8-symbol
 * preamble and a 10-byte payload, that comes to 41.2 ms. Common airtime
 * calculators agree.
 */
public final class LoRaAirtime {

    private LoRaAirtime() {
    }

    /** Seconds on air. {@code codingRate} is 1..4 for 4/5..4/8. */
    public static double seconds(int payloadBytes, int spreadingFactor, int bandwidthHz, int codingRate,
                                 int preambleSymbols) {
        if (spreadingFactor < 6 || spreadingFactor > 12 || codingRate < 1 || codingRate > 4 || payloadBytes < 0) {
            throw new IllegalArgumentException("LoRa parameters out of range");
        }
        double tSym = Math.pow(2, spreadingFactor) / bandwidthHz;
        int de = tSym >= 0.016 ? 1 : 0;
        double tPreamble = (preambleSymbols + 4.25) * tSym;
        double numerator = 8.0 * payloadBytes - 4.0 * spreadingFactor + 28 + 16 - 0;
        double symbols = 8 + Math.max(Math.ceil(numerator / (4.0 * (spreadingFactor - 2 * de))) * (codingRate + 4), 0);
        return tPreamble + symbols * tSym;
    }

    /** With the usual 125 kHz, CR 4/5 and 8-symbol preamble. */
    public static double seconds(int payloadBytes, int spreadingFactor) {
        return seconds(payloadBytes, spreadingFactor, 125_000, 1, 8);
    }

    /**
     * Largest payload at a spreading factor, EU868 at 125 kHz, using the
     * LoRaWAN regional limits (51 bytes at SF12–10, 115 at SF9, 222 at
     * SF8–7). Shalim does not speak LoRaWAN, but these limits keep each frame
     * inside the per-transmission dwell that gateways and regulators expect.
     */
    public static int maxPayload(int spreadingFactor) {
        if (spreadingFactor >= 10) {
            return 51;
        }
        if (spreadingFactor == 9) {
            return 115;
        }
        return 222;
    }
}
