/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2016 ForgeRock AS.
 */
package org.forgerock.openam.cts.worker.process;

import java.util.Collection;
import java.util.concurrent.CountDownLatch;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;

import org.apache.commons.lang.time.StopWatch;
import org.forgerock.openam.cts.api.CoreTokenConstants;
import org.forgerock.openam.cts.exceptions.CoreTokenException;
import org.forgerock.openam.cts.impl.query.worker.CTSWorkerQuery;
import org.forgerock.openam.cts.impl.queue.TaskDispatcher;
import org.forgerock.openam.cts.worker.CTSWorkerFilter;
import org.forgerock.openam.cts.worker.CTSWorkerTask;
import org.forgerock.openam.session.service.SessionAccessManager;
import org.forgerock.openam.sm.datalayer.api.query.PartialToken;

import com.iplanet.dpro.session.service.SessionAuditor;
import com.sun.identity.shared.debug.Debug;

/**
 * A process which handles max session time timeouts.
 */
public class MaxSessionTimeExpiredProcess extends CTSWorkerBaseProcess {

    private Debug debug;
    private SessionExpiryBatchHandler timeoutHandler;

    /**
     * Generates a new {@link CTSWorkerDeleteProcess} which can be used across multiple {@link CTSWorkerTask},
     * with various {@link CTSWorkerQuery} and {@link CTSWorkerFilter}.
     */
    @Inject
    public MaxSessionTimeExpiredProcess(
            final TaskDispatcher queue,
            final Provider<SessionAccessManager> accessManager,
            final SessionAuditor auditor,
            @Named(CoreTokenConstants.CTS_DEBUG) final Debug debug) {
        this.debug = debug;
        this.timeoutHandler = SessionExpiryBatchHandler.forMaxSessionTimeExpired(queue, accessManager, auditor);
    }

    @Override
    protected CountDownLatch handleBatch(final Collection<PartialToken> batch) throws CoreTokenException {
        return timeoutHandler.timeoutBatch(batch);
    }

    @Override
    protected void handleSucceeded(final StopWatch queryStopWatch, final StopWatch waitingStopWatch, final long total) {
        debug.message("Worker threads Time: {0}ms", Long.toString(waitingStopWatch.getTime()));
    }

    @Override
    protected void handleFailed(final Exception exception) {
        debug.error("Session lifetime timeout process failed", exception);
    }

}
