package org.shalim.transport;

/**
 * What each kind of transport can carry. These figures are design
 * assumptions for the platform implementations to meet. They are not
 * measurements, and each is explained below.
 *
 * <ul>
 *   <li><b>WIFI:</b> local network, TCP. Frames up to 1 MiB, broadcast up to
 *       1200 bytes (one UDP datagram, under the usual path MTU). Not
 *       observable when the hub runs the network; see
 *       {@code HubNetwork.isObservable}.</li>
 *   <li><b>CELLULAR:</b> as Wi-Fi for capacity, always observable. The
 *       operator sees who talks to whom, and when.</li>
 *   <li><b>BLUETOOTH_MESH:</b> 512-byte frames, which is the BLE GATT
 *       attribute ceiling and a common mesh-SDK message limit. Enough for log
 *       entries one or two at a time, not for bulk sync. Range leaks past
 *       walls, so it is observable to anyone nearby with a scanner.</li>
 *   <li><b>LORA:</b> see {@link LoRaAirtime#maxPayload}, with a 1% duty cycle.
 *       Beacons and single small messages only. Radio direction-finding makes
 *       any transmitter observable.</li>
 * </ul>
 */
public record TransportProfile(Transport.Kind kind, int maxPayloadBytes, int maxBroadcastBytes,
                               double dutyCycle, boolean supportsBulkSync, boolean observable) {

    public static final int WIFI_MAX_FRAME = 1 << 20;
    public static final int WIFI_MAX_BROADCAST = 1200;
    public static final int BLUETOOTH_MAX_FRAME = 512;

    public static TransportProfile wifi(boolean observable) {
        return new TransportProfile(Transport.Kind.WIFI, WIFI_MAX_FRAME, WIFI_MAX_BROADCAST, 1.0, true, observable);
    }

    public static TransportProfile cellular() {
        return new TransportProfile(Transport.Kind.CELLULAR, WIFI_MAX_FRAME, 0, 1.0, true, true);
    }

    public static TransportProfile bluetoothMesh() {
        return new TransportProfile(Transport.Kind.BLUETOOTH_MESH, BLUETOOTH_MAX_FRAME, BLUETOOTH_MAX_FRAME,
                1.0, false, true);
    }

    public static TransportProfile lora(int spreadingFactor) {
        int max = LoRaAirtime.maxPayload(spreadingFactor);
        return new TransportProfile(Transport.Kind.LORA, max, max, 0.01, false, true);
    }
}
