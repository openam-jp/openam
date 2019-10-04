/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2018 Open Source Solution Technology,Corp.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * 
 */

package jp.co.osstech.openam.authentication.modules.webauthn;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * The enum wraps up all of the possible user states in the Webauthn module
 * 
 */
public enum WebauthnAuthenticateModuleState {
    /*
     * the module is completed
     */
    COMPLETE(-1, "complete"),

    /*
     * start of the login process select login or key registration
     */
    LOGIN_START(1, "loginStart"),

    /*
     * start of the login process javascript get.credential
     */
    LOGIN_SCRIPT(2, "loginScript");

    private static final Map<Integer, WebauthnAuthenticateModuleState> lookup = new HashMap<Integer, WebauthnAuthenticateModuleState>();

    static {
        for (WebauthnAuthenticateModuleState ls : EnumSet.allOf(WebauthnAuthenticateModuleState.class)) {
            lookup.put(ls.intValue(), ls);
        }
    }

    private final int state;
    private final String name;

    private WebauthnAuthenticateModuleState(final int state, final String name) {
        this.state = state;
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public static WebauthnAuthenticateModuleState get(int screen) {
        return lookup.get(screen);
    }

    int intValue() {
        return state;
    }
}
