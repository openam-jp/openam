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

package jp.co.osstech.openam.config.upgrade;

import static org.forgerock.json.JsonValue.*;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOToken;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;
import java.security.AccessController;
import java.util.HashMap;
import java.util.Map;
import org.forgerock.openam.upgrade.UpgradeException;
import org.forgerock.openam.upgrade.UpgradeProgress;
import org.forgerock.openam.upgrade.UpgradeServices;
import org.forgerock.openam.upgrade.UpgradeUtils;
import org.forgerock.json.JsonValue;
import com.sun.identity.setup.ConfiguratorException;

/**
 * This class start the upgrade process.
 */

public class UpgradeServlet extends HttpServlet {

    private UpgradeServices upgrade;
    private SSOToken adminToken;
    private Debug debug = UpgradeUtils.debug;
    private boolean error = false;

    @Override
    public void init() throws ServletException {
        try {
            debug.message("Initializing upgrade subsystem.");
            adminToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
            upgrade = UpgradeServices.getInstance();
        } catch (Exception ue) {
            error = true;
            debug.error("An error occured, while initializing Upgrade page", ue);
        }
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String> params = new HashMap<String, String>();
        try {
            SystemProperties.initializeProperties(Constants.SYS_PROPERTY_INSTALL_TIME, "true");
            upgrade.upgrade(adminToken, true);
            SystemProperties.initializeProperties(Constants.SYS_PROPERTY_INSTALL_TIME, "false");
            params.put("message", "ok");
        } catch (UpgradeException | ConfiguratorException e) {
            params.put("error", e.getMessage());
            debug.error("Error occured while upgrading OpenAM", e);
        } finally {
            UpgradeProgress.closeOutputStream();
            writeJsonResponse(response, params);
        }
    }

    private void writeJsonResponse(HttpServletResponse response, Map<String, String> params) throws IOException {
        response.setContentType("application/json; charset=UTF-8");
        JsonValue json = json(params);
        PrintWriter out = response.getWriter();
        out.println(json.toString());
    }
}
