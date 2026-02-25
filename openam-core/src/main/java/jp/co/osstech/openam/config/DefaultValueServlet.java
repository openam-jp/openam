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

import static org.forgerock.json.JsonValue.*;

import java.io.IOException;
import java.io.File;
import java.util.HashMap;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.sun.identity.setup.SetupConstants;
import com.sun.identity.shared.Constants;
import com.sun.identity.setup.AMSetupServlet;
import com.sun.identity.setup.AMSetupUtils;
import org.forgerock.json.JsonValue;

/**
 * This class calculate and respond default values for the initial setup.
 */

public class DefaultValueServlet extends HttpServlet {
    public static String DEFAULT_DS_MGR_DN = "cn=Directory Manager";

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        JsonValue json = json(new HashMap<String, Object>());

        json.add(SetupConstants.CONFIG_VAR_SERVER_URL, getServerURL(request));
        json.add(SetupConstants.CONFIG_VAR_COOKIE_DOMAIN, request.getServerName());
        json.add(SetupConstants.CONFIG_VAR_PLATFORM_LOCALE, SetupConstants.DEFAULT_PLATFORM_LOCALE);
        json.add(SetupConstants.CONFIG_VAR_BASE_DIR, getBaseDir(request));

        json.add(SetupConstants.CONFIG_VAR_ROOT_SUFFIX, Constants.DEFAULT_ROOT_SUFFIX);
        json.add(SetupConstants.CONFIG_VAR_ENCRYPTION_KEY, AMSetupUtils.getRandomString());

        String hostName = request.getServerName();
        json.add(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT, getAvailablePort(hostName, 50389));
        json.add(SetupConstants.CONFIG_VAR_DIRECTORY_ADMIN_SERVER_PORT, getAvailablePort(hostName, 4444));
        json.add(SetupConstants.CONFIG_VAR_DIRECTORY_JMX_SERVER_PORT, getAvailablePort(hostName, 1689));
        json.add(SetupConstants.DS_EMB_REPL_REPLPORT1, getAvailablePort(hostName, 58989));
        json.add(SetupConstants.DS_EMB_REPL_ADMINPORT2, getAvailablePort(hostName, 50389));
        json.add(SetupConstants.DS_EMB_REPL_REPLPORT2, getAvailablePort(hostName, 50990));

        json.add(SetupConstants.DS_EMB_REPL_FLAG, "");
        json.add(SetupConstants.CONFIG_VAR_DATA_STORE, SetupConstants.SMS_EMBED_DATASTORE);
        json.add(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_SSL, "SIMPLE");
        json.add(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_HOST, "localhost");
        json.add(SetupConstants.CONFIG_VAR_DS_MGR_PWD, "");
        json.add(SetupConstants.CONFIG_VAR_DS_MGR_DN, DEFAULT_DS_MGR_DN);

        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().println(json.toString());
    }

    private String getServerURL(HttpServletRequest request) {
        String hostname = request.getServerName();
        int portnum = request.getServerPort();
        String protocol = request.getScheme();
        return protocol + "://" + hostname + ":" + portnum;
    }

    public String getBaseDir(HttpServletRequest request) {
        String basedir = AMSetupServlet.getPresetConfigDir();
        if ((basedir == null) || (basedir.length() == 0)) {
            String tmp = System.getProperty("user.home");
            if (File.separatorChar == '\\') {
                tmp = tmp.replace('\\', '/');
            }
            basedir = (tmp.endsWith("/")) ? tmp.substring(0, tmp.length() - 1) : tmp;
            String uri = request.getContextPath();
            basedir += uri;
        }

        return basedir;
    }

    public String getAvailablePort(String hostName, int portNumber) {
        return Integer.toString(AMSetupUtils.getFirstUnusedPort(hostName, portNumber, 1000));
    }
}
