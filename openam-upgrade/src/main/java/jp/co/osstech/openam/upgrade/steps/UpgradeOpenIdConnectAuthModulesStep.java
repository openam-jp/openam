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
 * Copyright 2019 Open Source Solution Technology Corporation
 */

package jp.co.osstech.openam.upgrade.steps;

import static org.forgerock.openam.upgrade.UpgradeServices.*;
import static org.forgerock.openam.utils.CollectionUtils.*;
import static org.forgerock.openam.authentication.modules.oidc.JwtHandlerConfig.*;

import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.forgerock.openam.sm.datalayer.api.ConnectionFactory;
import org.forgerock.openam.sm.datalayer.api.ConnectionType;
import org.forgerock.openam.sm.datalayer.api.DataLayer;
import org.forgerock.openam.upgrade.UpgradeException;
import org.forgerock.openam.upgrade.UpgradeStepInfo;
import org.forgerock.openam.upgrade.steps.AbstractUpgradeStep;

import com.iplanet.sso.SSOToken;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import com.sun.identity.sm.ServiceNotFoundException;

/**
 * This upgrade step looks in OpenID Connect id_token bearer module config to convert crypto-context-value
 * into client_secret.
 */
@UpgradeStepInfo(dependsOn = "org.forgerock.openam.upgrade.steps.UpgradeServiceSchemaStep")
public class UpgradeOpenIdConnectAuthModulesStep extends AbstractUpgradeStep {

    private static final String REPORT_DATA = "%REPORT_DATA%";
    private static final String SERVICE_NAME = "iPlanetAMAuthOpenIdConnectService";
    private Map<String, Set<String>> affectedRealms = new HashMap<String, Set<String>>();
    private int moduleCount = 0;

    @Inject
    public UpgradeOpenIdConnectAuthModulesStep(final PrivilegedAction<SSOToken> adminTokenAction,
            @DataLayer(ConnectionType.DATA_LAYER) final ConnectionFactory factory) {
        super(adminTokenAction, factory);
    }

    @Override
    public void initialize() throws UpgradeException {
        try {
            ServiceConfigManager scm = new ServiceConfigManager(SERVICE_NAME, getAdminToken());
            for (String realm : getRealmNames()) {
                ServiceConfig realmConfig = scm.getOrganizationConfig(realm, null);
                for (String moduleName : (Set<String>) realmConfig.getSubConfigNames()) {
                    ServiceConfig moduleConfig = realmConfig.getSubConfig(moduleName);
                    Map<String, Set<?>> attributes = getAttributes(moduleConfig);
                    check(attributes, realm, moduleName);
                }
            }
        } catch (ServiceNotFoundException e) {
            DEBUG.message("OpenID Connect id_token bearer modules not found. Nothing to upgrade", e);
        } catch (Exception ex) {
            DEBUG.error("An error occurred while trying to look for upgradable OpenID Connect id_token bearer modules", ex);
            throw new UpgradeException("Unable to retrieve OpenID Connect id_token bearer modules", ex);
        }
    }

    private Map<String, Set<?>> getAttributes(ServiceConfig moduleConfig) {
        return moduleConfig.getAttributes();
    }

    private void check(Map<String, Set<?>> attributes, String realm, String moduleName) {
        if (attributes.get(CRYPTO_CONTEXT_TYPE_KEY).contains(CRYPTO_CONTEXT_TYPE_CLIENT_SECRET)
                && isNotEmpty(attributes.get(CRYPTO_CONTEXT_VALUE_KEY))
                && isEmpty(attributes.get(KEY_CLIENT_SECRET))) {
            moduleCount++;
            flagModule(realm, moduleName);
        }
    }

    private void flagModule(String realm, String moduleName) {
        if (affectedRealms.containsKey(realm)) {
            affectedRealms.get(realm).add(moduleName);
        } else {
            affectedRealms.put(realm, asSet(moduleName));
        }
    }

    @Override
    public boolean isApplicable() {
        return !affectedRealms.isEmpty();
    }

    @Override
    public void perform() throws UpgradeException {
        try {
            ServiceConfigManager scm = new ServiceConfigManager(SERVICE_NAME, getAdminToken());
            for (Map.Entry<String, Set<String>> realm : affectedRealms.entrySet()) {
                ServiceConfig realmConfig = scm.getOrganizationConfig(realm.getKey(), null);
                for (String moduleName : realm.getValue()) {
                    ServiceConfig moduleConfig = realmConfig.getSubConfig(moduleName);
                    Map<String, Set<?>> attributes = getAttributes(moduleConfig);
                    Map<String, Set<?>> attribute = new HashMap();
                    attribute.put(KEY_CLIENT_SECRET, attributes.get(CRYPTO_CONTEXT_VALUE_KEY));
                    moduleConfig.setAttributes(attribute);
                    attribute = new HashMap();
                    attribute.put(CRYPTO_CONTEXT_VALUE_KEY, asSet(""));
                    moduleConfig.setAttributes(attribute);
                }
            }
        } catch (Exception ex) {
            DEBUG.error("An error occurred while trying to update OpenID Connect id_token bearer modules", ex);
            throw new UpgradeException("Unable to update OpenID Connect id_token bearer modules", ex);
        }
    }

    @Override
    public String getShortReport(String delimiter) {
        StringBuilder sb = new StringBuilder();
        if (moduleCount != 0) {
            sb.append(BUNDLE.getString("upgrade.openidconnect.auth.modules")).append(" (").append(moduleCount).append(')')
                    .append(delimiter);
        }
        return sb.toString();
    }

    @Override
    public String getDetailedReport(String delimiter) {
        Map<String, String> tags = new HashMap<String, String>();
        tags.put(LF, delimiter);
        StringBuilder sb = new StringBuilder();
        sb.append(getModulesReport("upgrade.openidconnect.auth.modules.updated", delimiter, affectedRealms));
        tags.put(REPORT_DATA, sb.toString());
        return tagSwapReport(tags, "upgrade.openidconnect.auth.modules.report");
    }

    private String getModulesReport(String messageKey, String delimiter, Map<String, Set<String>> flags) {
        if (flags.isEmpty()) {
            return "";
        }
        Map<String, String> tags = new HashMap<String, String>();
        tags.put(LF, delimiter);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Set<String>> entry : flags.entrySet()) {
            sb.append(BUNDLE.getString("upgrade.realm")).append(": ").append(entry.getKey()).append(delimiter);
            for (String module : entry.getValue()) {
                sb.append(INDENT).append(module).append(delimiter);
            }
        }
        tags.put(REPORT_DATA, sb.toString());
        return tagSwapReport(tags, messageKey);
    }
}
