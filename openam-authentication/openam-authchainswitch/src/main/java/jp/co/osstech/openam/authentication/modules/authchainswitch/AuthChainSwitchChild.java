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


package jp.co.osstech.openam.authentication.modules.authchainswitch;

import static jp.co.osstech.openam.authentication.modules.authchainswitch.AuthChainSwitchConstants.*;
import java.security.Principal;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import org.forgerock.openam.utils.StringUtils;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;


public class AuthChainSwitchChild extends AMLoginModule {

    // Name for the debug-log
    private final static String DEBUG_NAME = "AuthChainSwitchChild";
    private final static Debug debug = Debug.getInstance(DEBUG_NAME);
    private Principal principal = null;

    public AuthChainSwitchChild() {
        super();
    }


    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        debug.message("AuthChainSwitchChild::init");
        int authLevel = CollectionHelper.getIntMapAttr(options, CHILD_AUTHLEVEL, DEFAULT_AUTH_LEVEL, debug);
        try {
            setAuthLevel(authLevel);
        } catch (Exception e) {
            debug.error("Unable to set authLevel :[{}]",authLevel, e);
        }
    }

    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {

        debug.message("AuthChainSwitchChild :: process() state: [{}]", state);
        final HttpServletRequest req = getHttpServletRequest();

        if (!(req instanceof AuthChainSwitchHttpServletRequest)) {
            debug.error("AuthChainSwitchChild :: This authentication module was called directly.");
            throw new AuthLoginException("This authentication module was called directly.");
        }

        final AuthChainSwitchHttpServletRequest acs_req = (AuthChainSwitchHttpServletRequest) req;
        String userName = acs_req.getUserName();
        if (StringUtils.isEmpty(userName)) {
            debug.error("AuthChainSwitchChild :: userName is Empty.");
            throw new AuthLoginException("userName is Empty.");
        }

        debug.message("AuthChainSwitchChild :: userName : [{}]", userName);
        storeUsernamePasswd(userName, null);
        principal = new AuthChainSwitchPrincipal(userName);
        return ISAuthConstants.LOGIN_SUCCEED;
    }


    @Override
    public Principal getPrincipal() {
        return principal;
    }
}
