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

package jp.co.osstech.openam.console.base;

import com.iplanet.jato.ClientSession;
import com.iplanet.jato.RequestContextImpl;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A {@link RequestContextImpl} subclass that overrides {@link #getClientSession()} to return
 * a {@link DisabledClientSession}, preventing unsafe Java deserialization via the
 * {@code jato.clientSession} request parameter (potential RCE vector).
 *
 * <p>Servlet base classes should override {@code createRequestContext()} to instantiate
 * this class instead of the default {@link RequestContextImpl}.
 */
public class SafeRequestContextImpl extends RequestContextImpl {

    private ClientSession disabledClientSession;

    public SafeRequestContextImpl(String servletName, ServletContext servletContext,
            HttpServletRequest request, HttpServletResponse response) {
        super(servletName, servletContext, request, response);
    }

    @Override
    public ClientSession getClientSession() {
        if (disabledClientSession == null) {
            disabledClientSession = new DisabledClientSession(this);
        }
        return disabledClientSession;
    }
}
