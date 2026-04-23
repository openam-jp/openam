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
 * Portions Copyrighted 2026 OSSTech Corporation
 */

package jp.co.osstech.openam.authentication.modules.authchainswitch;

import static com.sun.identity.authentication.util.ISAuthConstants.LOGIN_START;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import javax.security.auth.callback.TextOutputCallback;

/**
 * Constants for the SAML2 SP SSO Auth Module.
 */
final class AuthChainSwitchConstants {

    /**
     * Arbitrary number of the max callbacks expected on an auth module's single step.
     */
    static final int MAX_CALLBACKS_INJECTED = 10;

    /*
     * Auth Module States.
     */
    /** Auth Module state - starting state. */
    static final int START = LOGIN_START;
    /** Auth Module state - Performing local login. */
    static final int LOGIN_1STEP  = 2;
    static final int LOGIN_2STEP  = 3;
    static final int LOGIN_3STEP  = 4;
    static final int LOGIN_4STEP  = 5;
    static final int LOGIN_5STEP  = 6;
    static final int LOGIN_6STEP  = 7;
    static final int LOGIN_7STEP  = 8;
    static final int LOGIN_8STEP  = 9;
    static final int LOGIN_9STEP  = 10;
    static final int LOGIN_10STEP = 11;

    /** Auth Module state - Error. */
    static final int STATE_ERROR = 12;

    /** authentication list state */
    static final int LOGIN_SELECT = 13;

    static final int DEFAULT_AUTH_LEVEL = 0;
    static final int DEFAULT_MAX_AGE = 30;
    /*
     * Auth Module Configuration XML Names.
     */

    static final String AUTH_ATTR_PREFIX = "osstech-am-auth-";

    /* Auth Level Module Configuration XML Name. */
    static final String AUTHLEVEL = "iplanet-am-auth-authchainswitch-auth-level";
    static final String CHILD_AUTHLEVEL = AUTH_ATTR_PREFIX + "authchainswithchild-auth-level";

    /* Service Name Configuration XML Name. */
    static final String AUTHCHAIN_ATTR_NAME = AUTH_ATTR_PREFIX + "attribute-name";
    static final String DEFAULT_AUTHCHAIN = AUTH_ATTR_PREFIX + "default-authchain-mapping";
    static final String ATTRVALUE_AUTHCHAIN_MAP = AUTH_ATTR_PREFIX + "attrvalue-authchain-mapping";
    static final String SESSION_UPGRADE_EMPTY_ALLOW = AUTH_ATTR_PREFIX + "session-upgrade-empty-allow";
    static final String COOKIE_NAME = AUTH_ATTR_PREFIX + "cookie-name";
    static final String COOKIE_MAX_AGE = AUTH_ATTR_PREFIX + "cookie-max-age";
    static final String MAPPING_VALUE_NOMATCH_ERROR = AUTH_ATTR_PREFIX + "mapping-value-nomatch-error";

    /* Child auth chain information */
    static final String AUTH_SESSION_PROPERTY_NAME = "AuthChainSwitchService";

    /**
     * Default Callback.
     */
    static final TextOutputCallback DEFAULT_CALLBACK = new ScriptTextOutputCallback("PLACEHOLDER");

    /**
     * Do not construct util classes.
     */
    private AuthChainSwitchConstants() {

    }

}
