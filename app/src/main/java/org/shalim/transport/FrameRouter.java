package org.shalim.transport;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Lets several services share one transport's single listener. Each frame
 * goes to every registered listener, and each ignores types that are not
 * its own.
 */
public final class FrameRouter implements Transport.FrameListener {

    private final List<Transport.FrameListener> listeners = new CopyOnWriteArrayList<>();

    public static FrameRouter on(Transport transport) {
        FrameRouter router = new FrameRouter();
        transport.setListener(router);
        return router;
    }

    public FrameRouter add(Transport.FrameListener listener) {
        listeners.add(listener);
        return this;
    }

    public void remove(Transport.FrameListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void onFrame(PeerEndpoint from, byte[] payload) {
        for (Transport.FrameListener l : listeners) {
            try {
                l.onFrame(from, payload);
            } catch (RuntimeException e) {
                // One faulty listener must not starve the rest.
            }
        }
    }
}
