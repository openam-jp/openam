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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * This is a wrapper class of <code>HttpServletRequest</code> used to add an
 * extra header to incoming requests.  This header will be checked later by
 * CheckOrigin authentication module for existence.  This mechanism prevents
 * child authentication chains from being accessed directly.
 */
public class AuthChainSwitchHttpServletRequest extends HttpServletRequestWrapper {

    private String userName = null;

    /**
     * Constructs a wrapper object from the incoming request.
     *
     * @param request Incoming <code>HttpServletRequest</code> object.
     */
    public AuthChainSwitchHttpServletRequest(HttpServletRequest request) {
        super(request);
    }

    public void setUserName(String user) {
        userName = user;
    }

    public String getUserName() {
        return userName;
    }
}
