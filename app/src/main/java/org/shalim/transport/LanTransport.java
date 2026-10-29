package org.shalim.transport;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shalim over a local IP network: the hub's Wi-Fi, or any LAN a desktop hub
 * instance sits on. This is the first real transport. Bluetooth mesh, LoRa
 * and cellular need platform radios and arrive with the Android build.
 *
 * <ul>
 *   <li><b>Unicast:</b> TCP. Each connection opens with
 *       {@code "SHLM" ‖ version ‖ listenPort(2)}, so the receiver knows where
 *       to reply. After that, frames are {@code length(4) ‖ bytes}, up to
 *       {@link TransportProfile#WIFI_MAX_FRAME}. Longer lengths close the
 *       connection. A sender reuses one connection per peer.</li>
 *   <li><b>Broadcast:</b> UDP datagrams {@code "SHLM" ‖ version ‖
 *       listenPort(2) ‖ frame} to the configured targets, by default the
 *       limited broadcast address on {@link #DEFAULT_UDP_PORT}. Used for claim
 *       queries, beacons and card gossip. Hearing a datagram is also how
 *       peers are discovered.</li>
 * </ul>
 *
 * <p>Nothing here is encrypted or authenticated, and nothing needs to be:
 * everything except claim queries, beacons and public cards travels inside a
 * {@link SecureChannel} session, and those three are built to be safe in the
 * clear. Treat any frame from this class as hostile until a session vouches
 * for it.
 */
public final class LanTransport implements Transport {

    public static final int DEFAULT_UDP_PORT = 47_474;
    private static final byte[] MAGIC = {'S', 'H', 'L', 'M'};
    private static final int VERSION = 1;
    private static final Duration PEER_EXPIRY = Duration.ofMinutes(10);

    private final int requestedTcpPort;
    private final int udpPort;
    private final List<InetSocketAddress> broadcastTargets;
    private final boolean observable;
    private final Clock clock;

    private final Map<String, PeerEndpoint> endpoints = new ConcurrentHashMap<>();
    private final Map<String, Connection> connections = new ConcurrentHashMap<>();
    private volatile FrameListener listener;
    private volatile boolean running;
    private ServerSocket server;
    private DatagramSocket udp;

    /**
     * @param tcpPort          0 for any free port
     * @param udpPort          port to receive broadcasts on
     * @param broadcastTargets where broadcasts go; empty means 255.255.255.255:udpPort
     * @param observable       from {@code HubNetwork.isObservable()}
     */
    public LanTransport(int tcpPort, int udpPort, List<InetSocketAddress> broadcastTargets, boolean observable,
                        Clock clock) {
        this.requestedTcpPort = tcpPort;
        this.udpPort = udpPort;
        this.broadcastTargets = broadcastTargets.isEmpty()
                ? List.of(new InetSocketAddress("255.255.255.255", udpPort)) : List.copyOf(broadcastTargets);
        this.observable = observable;
        this.clock = clock;
    }

    public LanTransport(boolean observable) {
        this(0, DEFAULT_UDP_PORT, List.of(), observable, Clock.systemUTC());
    }

    /** Binds sockets and starts the listener threads. */
    public synchronized LanTransport start() throws IOException {
        if (running) {
            return this;
        }
        server = new ServerSocket(requestedTcpPort);
        udp = new DatagramSocket(null);
        udp.setReuseAddress(true);
        udp.setBroadcast(true);
        udp.bind(new InetSocketAddress(udpPort));
        running = true;
        daemon("lan-accept", this::acceptLoop);
        daemon("lan-udp", this::udpLoop);
        return this;
    }

    public int tcpPort() {
        return server.getLocalPort();
    }

    // --- Transport --------------------------------------------------------

    @Override
    public Kind kind() {
        return Kind.WIFI;
    }

    @Override
    public boolean isAvailable() {
        return running;
    }

    @Override
    public int maxPayloadBytes() {
        return TransportProfile.WIFI_MAX_FRAME;
    }

    @Override
    public int maxBroadcastBytes() {
        return TransportProfile.WIFI_MAX_BROADCAST;
    }

    @Override
    public double dutyCycle() {
        return 1.0;
    }

    @Override
    public boolean supportsBulkSync() {
        return true;
    }

    @Override
    public boolean isObservable() {
        return observable;
    }

    @Override
    public List<PeerEndpoint> discoverPeers() {
        Instant cutoff = clock.instant().minus(PEER_EXPIRY);
        List<PeerEndpoint> out = new ArrayList<>();
        for (PeerEndpoint p : endpoints.values()) {
            Instant seen = p.getLastContactAt();
            if (seen != null && seen.isAfter(cutoff)) {
                out.add(p);
            }
        }
        return out;
    }

    /** A peer known by address in advance: a second hub instance on a fixed host, say. */
    public PeerEndpoint peerAt(String host, int port) {
        return endpointFor(host + ":" + port);
    }

    @Override
    public boolean send(PeerEndpoint peer, byte[] payload) {
        if (!running || peer == null || payload.length > maxPayloadBytes()) {
            return false;
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            Connection c = connectionTo(peer.getAddress());
            if (c != null && c.write(payload)) {
                return true;
            }
            if (c != null) {
                c.close();
            }
        }
        return false;
    }

    @Override
    public boolean broadcast(byte[] payload) {
        if (!running || payload.length > maxBroadcastBytes()) {
            return false;
        }
        byte[] datagram = new byte[MAGIC.length + 3 + payload.length];
        writeHeader(datagram);
        System.arraycopy(payload, 0, datagram, MAGIC.length + 3, payload.length);
        boolean any = false;
        for (InetSocketAddress target : broadcastTargets) {
            try {
                udp.send(new DatagramPacket(datagram, datagram.length, target));
                any = true;
            } catch (IOException e) {
                // One unreachable target does not stop the others.
            }
        }
        return any;
    }

    @Override
    public void setListener(FrameListener listener) {
        this.listener = listener;
    }

    @Override
    public synchronized void close() {
        running = false;
        try {
            if (server != null) {
                server.close();
            }
        } catch (IOException ignored) {
            // closing anyway
        }
        if (udp != null) {
            udp.close();
        }
        for (Connection c : connections.values()) {
            c.close();
        }
        connections.clear();
    }

    // --- internals --------------------------------------------------------

    private void writeHeader(byte[] into) {
        System.arraycopy(MAGIC, 0, into, 0, MAGIC.length);
        into[MAGIC.length] = (byte) VERSION;
        int port = tcpPort();
        into[MAGIC.length + 1] = (byte) (port >>> 8);
        into[MAGIC.length + 2] = (byte) port;
    }

    private PeerEndpoint endpointFor(String address) {
        return endpoints.computeIfAbsent(address, a -> new PeerEndpoint(Kind.WIFI, a));
    }

    private void deliver(String fromAddress, byte[] frame) {
        PeerEndpoint from = endpointFor(fromAddress);
        from.contact(clock.instant());
        FrameListener l = listener;
        if (l != null) {
            try {
                l.onFrame(from, frame);
            } catch (RuntimeException e) {
                // A listener bug must not kill the connection's reader.
            }
        }
    }

    private Connection connectionTo(String address) {
        Connection existing = connections.get(address);
        if (existing != null && existing.isOpen()) {
            return existing;
        }
        int colon = address.lastIndexOf(':');
        if (colon < 0) {
            return null;
        }
        try {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(address.substring(0, colon),
                    Integer.parseInt(address.substring(colon + 1))), 5_000);
            s.setTcpNoDelay(true);
            byte[] header = new byte[MAGIC.length + 3];
            writeHeader(header);
            s.getOutputStream().write(header);
            Connection c = new Connection(s, address);
            connections.put(address, c);
            daemon("lan-read-" + address, c::readLoop);
            return c;
        } catch (IOException | NumberFormatException e) {
            return null;
        }
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = server.accept();
                daemon("lan-in", () -> handshakeIncoming(s));
            } catch (IOException e) {
                if (!running) {
                    return;
                }
            }
        }
    }

    private void handshakeIncoming(Socket s) {
        try {
            s.setSoTimeout(10_000);
            DataInputStream in = new DataInputStream(s.getInputStream());
            byte[] header = new byte[MAGIC.length + 3];
            in.readFully(header);
            int port = checkHeader(header);
            if (port < 0) {
                s.close();
                return;
            }
            s.setSoTimeout(0);
            String address = s.getInetAddress().getHostAddress() + ":" + port;
            Connection c = new Connection(s, address);
            Connection previous = connections.put(address, c);
            if (previous != null && previous != c) {
                previous.close();
            }
            c.readLoop();
        } catch (IOException e) {
            try {
                s.close();
            } catch (IOException ignored) {
                // already failing
            }
        }
    }

    private void udpLoop() {
        byte[] buf = new byte[MAGIC.length + 3 + TransportProfile.WIFI_MAX_BROADCAST];
        while (running) {
            try {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                udp.receive(p);
                if (p.getLength() <= MAGIC.length + 3) {
                    continue;
                }
                byte[] data = new byte[p.getLength()];
                System.arraycopy(p.getData(), p.getOffset(), data, 0, data.length);
                int port = checkHeader(data);
                if (port < 0 || isSelf(p.getAddress(), port)) {
                    continue;
                }
                byte[] frame = new byte[data.length - MAGIC.length - 3];
                System.arraycopy(data, MAGIC.length + 3, frame, 0, frame.length);
                deliver(p.getAddress().getHostAddress() + ":" + port, frame);
            } catch (SocketException e) {
                if (!running) {
                    return;
                }
            } catch (IOException e) {
                // a bad datagram; keep listening
            }
        }
    }

    private boolean isSelf(InetAddress from, int port) {
        if (port != tcpPort()) {
            return false;
        }
        try {
            return from.isLoopbackAddress() || java.net.NetworkInterface.getByInetAddress(from) != null;
        } catch (SocketException e) {
            return false;
        }
    }

    /** Listen port from a valid header, or -1. */
    private static int checkHeader(byte[] header) {
        for (int i = 0; i < MAGIC.length; i++) {
            if (header[i] != MAGIC[i]) {
                return -1;
            }
        }
        if ((header[MAGIC.length] & 0xff) != VERSION) {
            return -1;
        }
        return ((header[MAGIC.length + 1] & 0xff) << 8) | (header[MAGIC.length + 2] & 0xff);
    }

    private static void daemon(String name, Runnable body) {
        Thread t = new Thread(body, name);
        t.setDaemon(true);
        t.start();
    }

    /** One TCP connection, either direction. */
    private final class Connection {
        private final Socket socket;
        private final String address;
        private final DataOutputStream out;

        Connection(Socket socket, String address) throws IOException {
            this.socket = socket;
            this.address = address;
            this.out = new DataOutputStream(socket.getOutputStream());
        }

        boolean isOpen() {
            return !socket.isClosed();
        }

        synchronized boolean write(byte[] frame) {
            try {
                out.writeInt(frame.length);
                out.write(frame);
                out.flush();
                return true;
            } catch (IOException e) {
                return false;
            }
        }

        void readLoop() {
            try {
                DataInputStream in = new DataInputStream(socket.getInputStream());
                while (running) {
                    int length = in.readInt();
                    if (length < 0 || length > TransportProfile.WIFI_MAX_FRAME) {
                        break;
                    }
                    byte[] frame = new byte[length];
                    in.readFully(frame);
                    deliver(address, frame);
                }
            } catch (IOException e) {
                // peer went away
            } finally {
                close();
            }
        }

        void close() {
            connections.remove(address, this);
            try {
                socket.close();
            } catch (IOException ignored) {
                // closing anyway
            }
        }
    }
}
