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
 * Copyright 2026 OSSTech Corporation
 */
package org.forgerock.openam.core.rest.session.query.impl;

import static org.forgerock.openam.session.SessionConstants.SESSION_DEBUG;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.session.query.SessionQueryType;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.session.SessionCache;

import com.google.inject.Key;
import com.google.inject.name.Names;
import com.iplanet.dpro.session.Session;
import com.iplanet.dpro.session.SessionException;
import com.iplanet.dpro.session.SessionID;
import com.iplanet.dpro.session.service.SessionService;
import com.iplanet.dpro.session.share.SessionInfo;
import com.iplanet.sso.SSOToken;
import com.sun.identity.shared.debug.Debug;

/**
 * Provides an implementation of the SessionQueryType that is used for local OpenAM instance.
 */
public class LocalSessionQuery implements SessionQueryType {

    private static Debug debug = InjectorHolder.getInstance(Key.get(Debug.class, Names.named(SESSION_DEBUG)));

    private final SessionService sessionService;
    private final SessionCache sessionCache;

    /**
     * Constructor.
     */
    public LocalSessionQuery() {
        sessionService = InjectorHolder.getInstance(SessionService.class);
        sessionCache = InjectorHolder.getInstance(SessionCache.class);
    }

    @Override
    public Collection<SessionInfo> getSessions(String pattern) {
        List<SessionInfo> result = new LinkedList<SessionInfo>();
        try {
            int status[] = { 0 };
            SSOToken adminToken = RestUtils.getToken();
            Session callerSession = sessionCache.getSession(new SessionID(adminToken.getTokenID().toString()));
            List<SessionInfo> infos = sessionService.getValidSessions(callerSession, pattern, status);
            result.addAll(infos);
        } catch (SessionException e) {
            debug.error("LocalSessionQuery.getSessions() : Unable to get valid sessions", e);
        }
        return result;
    }
}
