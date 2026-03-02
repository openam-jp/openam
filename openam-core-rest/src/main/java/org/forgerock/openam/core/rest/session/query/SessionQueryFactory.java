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
 * Copyright 2013-2015 ForgeRock AS.
 * Portions copyright 2026 OSSTech Corporation
 */

package org.forgerock.openam.core.rest.session.query;

import static org.forgerock.openam.session.SessionConstants.SESSION_DEBUG;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.session.query.impl.LocalSessionQuery;
import org.forgerock.openam.core.rest.session.query.impl.RemoteSessionQuery;

import com.google.inject.Key;
import com.google.inject.name.Names;
import com.iplanet.services.naming.ServerEntryNotFoundException;
import com.iplanet.services.naming.WebtopNaming;
import com.sun.identity.shared.debug.Debug;

/**
 * SessionQueryFactory provides a means of generating SessionQueryTypes based on the server id that is provided.
 *
 * @since 11.0.0
 */
public class SessionQueryFactory {

    private static Debug debug = InjectorHolder.getInstance(Key.get(Debug.class, Names.named(SESSION_DEBUG)));

    /**
     * Implementation is currently hard-coded to return the RemoteSessionQuery.
     *
     * @param serverId Non null server id.
     * @return A non null SessionQueryType based on the id.
     */
    public SessionQueryType getSessionQueryType(String serverId) {
        try {
            if (WebtopNaming.getAMServerID().equals(serverId)) {
                return new LocalSessionQuery();
            }
        } catch (ServerEntryNotFoundException e) {
            debug.error("SessionQueryFactory.getSessionQueryType() : Unable to create local query instance", e);
        }
        return new RemoteSessionQuery(serverId);
    }
}
