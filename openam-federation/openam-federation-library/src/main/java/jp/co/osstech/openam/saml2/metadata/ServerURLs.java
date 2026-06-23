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
package jp.co.osstech.openam.saml2.metadata;

import java.security.AccessController;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.common.configuration.ServerConfiguration;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.sm.ChoiceValues;
import com.sun.identity.sm.SMSException;

/**
 * This class provides a set of all server URL in a current deployment.
 */
public class ServerURLs extends ChoiceValues {

    /**
     * Retruns a map of all server URL in a current deployment.
     *
     * @return A map of all server URL in a current deployment. The keys and the
     *         values are <code>String</code> of the server URL.
     */
    @Override
    public Map getChoiceValues() {
        SSOToken adminToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
        try {
            Set<String> serverURLs = ServerConfiguration.getServers(adminToken);
            Map<String, String> answer = new HashMap<>();
            for (String serverURL : serverURLs) {
                answer.put(serverURL, serverURL);
            }
            return answer;
        } catch (SSOException | SMSException e) {
            return new HashMap<>();
        }

    }

}
