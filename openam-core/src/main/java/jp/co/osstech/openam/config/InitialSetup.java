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

package jp.co.osstech.openam.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.identity.setup.AMSetupServlet;
import com.sun.identity.setup.ConfiguratorException;
import com.sun.identity.setup.HttpServletRequestWrapper;
import com.sun.identity.setup.HttpServletResponseWrapper;
import com.sun.identity.setup.SetupConstants;
import org.forgerock.json.JsonValue;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is class start the initial setup process with parameters sent from the
 * client.
 */

public class InitialSetup extends HttpServlet {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, String>> MAP_TYPE = new TypeReference<Map<String, String>>() {
    };

    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {

        HttpServletRequestWrapper request = new HttpServletRequestWrapper(req);
        HttpServletResponseWrapper response = new HttpServletResponseWrapper(res);

        Map<String, String> requestParams = MAPPER.readValue(req.getReader(), MAP_TYPE);
        for (String key : requestParams.keySet()) {
            request.addParameter(key, requestParams.get(key));
        }

        /*
         * Set the data store information
         */

        String tmp = (String) request.getParameter(SetupConstants.USER_STORE);

        if (tmp != null && tmp.equals("true")) {
            Map store = new HashMap(12);
            tmp = (String) request.getParameter(SetupConstants.USER_STORE_HOST);
            store.put(SetupConstants.USER_STORE_HOST, tmp);

            tmp = (String) request.getParameter(SetupConstants.USER_STORE_SSL);
            store.put(SetupConstants.USER_STORE_SSL, tmp);

            tmp = (String) request.getParameter(SetupConstants.USER_STORE_PORT);
            store.put(SetupConstants.USER_STORE_PORT, tmp);
            tmp = (String) request.getParameter(SetupConstants.USER_STORE_ROOT_SUFFIX);
            store.put(SetupConstants.USER_STORE_ROOT_SUFFIX, tmp);
            tmp = (String) request.getParameter(SetupConstants.USER_STORE_LOGIN_ID);
            store.put(SetupConstants.USER_STORE_LOGIN_ID, tmp);
            tmp = (String) request.getParameter(SetupConstants.USER_STORE_LOGIN_PWD);
            store.put(SetupConstants.USER_STORE_LOGIN_PWD, tmp);
            tmp = (String) request.getParameter(SetupConstants.USER_STORE_TYPE);
            store.put(SetupConstants.USER_STORE_TYPE, tmp);

            request.addParameter(SetupConstants.USER_STORE, store);
        }

        // site configuration is passed as a map of the site information
        Map siteConfig = new HashMap(3);
        String loadBalancerHost = (String) request.getParameter(SetupConstants.LB_SITE_NAME);
        String primaryURL = (String) request.getParameter(SetupConstants.LB_PRIMARY_URL);
        // Assume no Session HA Failover.
        Boolean isSessionHASFOEnabled = false;
        if (request.getParameter(SetupConstants.LB_SESSION_HA_SFO) != null) {
            isSessionHASFOEnabled = Boolean.valueOf((String) request.getParameter(SetupConstants.LB_SESSION_HA_SFO));
        }
        if (loadBalancerHost != null && !loadBalancerHost.isEmpty()) {
            siteConfig.put(SetupConstants.LB_SITE_NAME, loadBalancerHost);
            siteConfig.put(SetupConstants.LB_PRIMARY_URL, primaryURL);
            siteConfig.put(SetupConstants.LB_SESSION_HA_SFO, isSessionHASFOEnabled.toString());
            request.addParameter(SetupConstants.CONFIG_VAR_SITE_CONFIGURATION, siteConfig);
        }

        Map<String, String> responseParams = new HashMap<String, String>();
        try {
            if (AMSetupServlet.processRequest(request, response)) {
                responseParams.put("message", "true");
            } else {
                responseParams.put("error", AMSetupServlet.getErrorMessage());
            }
        } catch (ConfiguratorException cfe) {
            responseParams.put("error", cfe.getMessage());
        }
        res.setContentType("application/json; charset=UTF-8");
        JsonValue responseJson = new JsonValue(responseParams);
        res.getWriter().print(responseJson.toString());
    }

}
