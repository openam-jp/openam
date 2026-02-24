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

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openam.utils.Time.currentTimeMillis;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.AccessController;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.iplanet.sso.SSOToken;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.setup.AMSetupServlet;
import com.sun.identity.shared.debug.Debug;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.upgrade.UpgradeServices;
import org.forgerock.openam.upgrade.UpgradeUtils;
import org.forgerock.openam.upgrade.VersionUtils;

/**
 * This class check whether the server needs to be upgraded.
 */

public class CheckUpgrade extends HttpServlet {

    private UpgradeServices upgrade = null;
    private SSOToken adminToken = null;
    private Debug debug = UpgradeUtils.debug;
    private boolean error = false;
    private boolean upgradeSystemInitialized = false;

    private void initializeUpgradeSystem() {
        if (upgradeSystemInitialized) {
            return;
        }
        upgradeSystemInitialized = true;
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
        boolean isSaveReportRequest = Boolean.parseBoolean(request.getParameter("saveReport"));
        boolean needUpgrade = VersionUtils.isVersionNewer();
        boolean upgradeCompleted = AMSetupServlet.isUpgradeCompleted();
        Map<String, String> params = new HashMap<String, String>();

        params.put("needUpgrade", String.valueOf(needUpgrade));
        params.put("upgradeCompleted", String.valueOf(upgradeCompleted));
        if (!needUpgrade) {
            writeJsonResponse(response, params);
            return;
        }
        initializeUpgradeSystem();
        if (error) {
            params.put("error", "true");
            writeJsonResponse(response, params);
            return;
        }
        if (isSaveReportRequest) {
            saveReport(response);
        } else {
            params.put("currentVersion", VersionUtils.getCurrentVersion());
            params.put("newVersion", VersionUtils.getWarFileVersion());
            params.put("changelist", upgrade.generateShortUpgradeReport(adminToken, true));
            writeJsonResponse(response, params);
        }
    }

    private void writeJsonResponse(HttpServletResponse response, Map<String, String> params) throws IOException {
        response.setContentType("application/json; charset=UTF-8");
        JsonValue json = json(params);
        PrintWriter out = response.getWriter();
        out.println(json.toString());
    }

    private void saveReport(HttpServletResponse response) throws IOException {
        response.setContentType("application/force-download; charset=\"UTF-8\"");
        response.setHeader("Content-Disposition", "attachment; filename=\"upgradereport." + currentTimeMillis() + "\"");
        response.setHeader("Content-Description", "File Transfer");
        response.getWriter().println(upgrade.generateDetailedUpgradeReport(adminToken, false));
    }
}
