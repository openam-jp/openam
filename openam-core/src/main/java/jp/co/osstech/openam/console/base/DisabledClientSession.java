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
import com.iplanet.jato.RequestContext;
import com.sun.identity.shared.debug.Debug;

import java.lang.reflect.Field;

/**
 * A {@link ClientSession} subclass that completely ignores the {@code jato.clientSession}
 * request parameter, preventing RCE via unsafe Java deserialization.
 *
 * <p>The parent's {@code deserializeAttributes()} is never called; instead the session is
 * always marked valid with empty attributes by setting the {@code valid} field directly
 * via reflection.
 */
public class DisabledClientSession extends ClientSession {

    private static final Debug DEBUG = Debug.getInstance("amConsole");

    private boolean deserialized = false;

    protected DisabledClientSession(RequestContext context) {
        super(context);
    }

    /**
     * Overrides the parent's unsafe deserialization by doing nothing.
     *
     * <p>The {@code jato.clientSession} request parameter is always ignored regardless of
     * whether it is present, preventing any deserialization from taking place. The session
     * is simply marked valid with empty attributes.
     */
    @Override
    protected void deserializeAttributes() {
        if (deserialized) {
            return;
        }
        deserialized = true;
        setValidField(true);
    }

    private void setValidField(boolean value) {
        try {
            Field f = ClientSession.class.getDeclaredField("valid");
            f.setAccessible(true);
            f.setBoolean(this, value);
        } catch (Exception e) {
            DEBUG.error("DisabledClientSession.setValidField: could not set valid field via reflection", e);
        }
    }
}
