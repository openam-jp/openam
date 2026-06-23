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
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.iplanet.services.naming.WebtopNaming;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.common.SystemTimerPool;
import com.sun.identity.common.configuration.ServerConfiguration;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.setup.SetupListener;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.sm.OrganizationConfigManager;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfigManager;
import com.sun.identity.sm.ServiceListener;

/**
 * The class <code>MetadataReloadTaskManager</code> manages
 * <code>MetadataReloadTask</code> instances for each realm. It listens service
 * configurations and the system startup, cancels scheduled tasks or schedule
 * new tasks if needed.
 */
public class MetadataReloadTaskManager implements ServiceListener, SetupListener {

    private static final Debug DEBUG = Debug.getInstance(MetadataReloadTaskManager.class.getSimpleName());

    private static final String SERVICE_NAME = MetadataReloadTaskFactory.METADATA_RELOAD_SERVICE_NAME;
    private static final String SERVICE_VERSION = MetadataReloadTaskFactory.SERVICE_VERSION;

    private static Map<String, MetadataReloadTask> tasks = new ConcurrentHashMap<>();

    @Override
    public void globalConfigChanged(String serviceName, String version, String groupName, String serviceComponent,
            int type) {
        // do nothing
        return;
    }

    @Override
    public void organizationConfigChanged(String serviceName, String version, String orgName, String groupName,
            String serviceComponent, int type) {
        if (!SERVICE_NAME.equals(serviceName)) {
            return;
        }
        if (!SERVICE_VERSION.equals(version)) {
            return;
        }

        String realm = DNMapper.orgNameToRealmName(orgName);
        synchronized(tasks) {
            MetadataReloadTask currentTask = tasks.remove(realm);
            if (currentTask != null) {
                currentTask.cancel();
            }
            if (type == REMOVED) {
                return;
            }

            try {
                scheduleTask(realm);
            } catch (SMSException | SSOException | SAML2MetaException e) {
                DEBUG.error("An error occurs while scheduling the task", e);
            }
        }
    }

    @Override
    public void schemaChanged(String serviceName, String version) {
        // do nothing
        return;
    }

    @Override
    public void setupComplete() {
        try {
            registerServiceListener();
        } catch (SMSException | SSOException e) {
            DEBUG.error("An error occurs while registering the listener", e);
            return;
        }

        Set<String> realms;
        try {
            realms = getAllRealms();
        } catch (SMSException e) {
            DEBUG.error("Can't get all realm names", e);
            return;
        }

        for (String realm : realms) {
            try {
                scheduleTask(realm);
            } catch (SSOException | SMSException | SAML2MetaException e) {
                DEBUG.error("An error occurs while scheduling the task", e);
            }
        }
    }

    private static SSOToken getAdminToken() {
        return AccessController.doPrivileged(AdminTokenAction.getInstance());
    }

    private static Set<String> getAllRealms() throws SMSException {
        Set<String> allRealms = new HashSet();
        String topRealm = "/";
        OrganizationConfigManager ocm = new OrganizationConfigManager(getAdminToken(), topRealm);
        Set<String> subRealms = (Set<String>) ocm.getSubOrganizationNames("*", true);
        for (String subRealm : subRealms) {
            allRealms.add(topRealm + subRealm);
        }
        allRealms.add(topRealm);
        return allRealms;
    }

    private static Date calcNextRun(LocalTime executeTime) {
        LocalDateTime nowDateTime = LocalDateTime.now();
        LocalDate nowDate = nowDateTime.toLocalDate();
        LocalTime nowTime = nowDateTime.toLocalTime();

        if (executeTime.isAfter(nowTime)) {
            LocalDateTime nextRun = LocalDateTime.of(nowDate, executeTime);
            return localDateTimeToDate(nextRun);
        } else {
            LocalDateTime nextRun = LocalDateTime.of(nowDate.plusDays(1), executeTime);
            return localDateTimeToDate(nextRun);
        }
    }

    private static Date localDateTimeToDate(LocalDateTime localDateTime) {
        ZoneId zone = ZoneId.systemDefault();
        ZonedDateTime zonedDateTime = ZonedDateTime.of(localDateTime, zone);
        Instant instant = zonedDateTime.toInstant();
        return Date.from(instant);
    }

    private void registerServiceListener() throws SMSException, SSOException {
        ServiceConfigManager scm = new ServiceConfigManager(getAdminToken(), SERVICE_NAME, SERVICE_VERSION);
        scm.addListener(new MetadataReloadTaskManager());
    }

    private void scheduleTask(String realm)
            throws SSOException, SMSException, SAML2MetaException {
        MetadataReloadTaskFactory factory = new MetadataReloadTaskFactory();
        Optional<MetadataReloadTask> optTask = factory.getReloadTask(realm);
        Optional<MetadataReloadConfig> optConfig = factory.getReloadConfig(realm);
        if (!optTask.isPresent() || !optConfig.isPresent()) {
            DEBUG.message("The realm: {} is not configured for the metadata reload task or has invalid configuration.",
                    realm);
            return;
        }
        MetadataReloadTask task = optTask.get();
        MetadataReloadConfig config = optConfig.get();

        if (!shouldRunInThisServer(config)) {
            return;
        }

        LocalTime executeTime = config.executeTime();
        Date nextRun = calcNextRun(executeTime);
        SystemTimerPool.getTimerPool().schedule(task, nextRun);
        tasks.put(realm, task);
    }

    // To aviod conflicts by updating configuration from more than one server
    // instance, we should run the task in only one server instance.
    private boolean shouldRunInThisServer(MetadataReloadConfig config) throws SMSException, SSOException {
        if (singleInstanceOnly()) {
            DEBUG.message("There is only one server instance. The task is executed in this server");
            return true;
        }
        String thisServerURL = WebtopNaming.getLocalServer();
        DEBUG.message("URL of this server: {}", thisServerURL);
        if (thisServerURL != null && thisServerURL.equals(config.executeServerURL())) {
            DEBUG.message("The server URL matches this server. The task is executed in this server");
            return true;
        }
        DEBUG.message("The server URL doesn't match this server. The task is not executed in this server");
        return false;
    }

    private boolean singleInstanceOnly() throws SMSException, SSOException {
        Set<String> allServers = ServerConfiguration.getServers(getAdminToken());
        return allServers.size() == 1;
    }
}
