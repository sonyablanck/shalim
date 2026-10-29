package org.shalim.query;

import java.time.Instant;
import org.shalim.hub.Hub;
import org.shalim.hub.HubRuntime;
import org.shalim.identity.Membership;

/**
 * Context passed through the query gate pipeline. Each gate can short-circuit by
 * returning a rejection result.
 */
public class QueryContext {

    private final Hub hub;
    private final HubRuntime runtime;
    private final HubQuery query;
    private final Membership membership;
    private final Instant now;

    public QueryContext(Hub hub, HubRuntime runtime, HubQuery query, Membership membership, Instant now) {
        this.hub = hub;
        this.runtime = runtime;
        this.query = query;
        this.membership = membership;
        this.now = now;
    }

    public Hub getHub() {
        return hub;
    }

    public HubRuntime getRuntime() {
        return runtime;
    }

    public HubQuery getQuery() {
        return query;
    }

    public Membership getMembership() {
        return membership;
    }

    public Instant getNow() {
        return now;
    }
}
