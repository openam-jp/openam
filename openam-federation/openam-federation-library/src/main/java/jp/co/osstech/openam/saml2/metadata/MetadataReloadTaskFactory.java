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

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.forgerock.guice.core.InjectorHolder;

import com.iplanet.sso.SSOException;
import com.sun.identity.common.configuration.MapValueParser;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.datastruct.ValueNotFoundException;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

import jp.co.osstech.openam.saml2.metadata.MetadataReloadConfig.TargetRole;

/**
 * The class <code>MetadataReloadTaskFactory</code> is the factory class for
 * creating the instance of <code>MetadataReloadTask</code>
 */
public class MetadataReloadTaskFactory {

    private static final Debug DEBUG = Debug.getInstance(MetadataReloadTaskFactory.class.getSimpleName());

    static final String METADATA_RELOAD_SERVICE_NAME = "SAML2MetadataAutoReload";
    static final String SERVICE_VERSION = "1.0";

    private static final String METADATA_URL_BACKUP_MAP = "openam-saml2-metadata-auto-reload-metadata-url-backup-map";
    private static final String EXECUTE_TIME = "openam-saml2-metadata-auto-reload-execute-time";
    private static final String EXECTE_SERVER_URL = "openam-saml2-metadata-auto-reload-execute-server-url";
    private static final String TARGET_ROLE = "openam-saml2-metadata-auto-reload-target-role";
    private static final String INCLUDE_ENTITIES = "openam-saml2-metadata-auto-reload-include-entities";
    private static final String EXCLUDE_ENTITIES = "openam-saml2-metadata-auto-reload-exclude-entities";
    private static final String ALLOW_CREATE_ENTITIES = "openam-saml2-metadata-auto-reload-allow-create-entities";
    private static final String CHECK_EXPIRATION_DATE = "openam-saml2-metadata-auto-reload-check-expiration-date";
    private static final String VALIDATE_SIGNATURE = "openam-saml2-metadata-auto-reload-validate-signature";

    private static final MapValueParser MAP_VALUE_PARSER = new MapValueParser();

    /**
     * Create the instance of <code>MetadataReloadTask</code> given realm.
     *
     * @param realm
     * @return Optional <code>MetadataReloadTask</code>. Return <code>null</code>
     *         if the service is not configured for given realm.
     * @throws SMSException       If an error occurs while retrieving a service
     *                            configuration.
     * @throws SSOException       If can't retrieve a service configuration for
     *                            the realm.
     * @throws SAML2MetaException if can't retrieve a
     *                            <code>SAML2MetaManager</code> instance.
     */
    public Optional<MetadataReloadTask> getReloadTask(final String realm)
            throws SMSException, SSOException, SAML2MetaException {
        Optional<MetadataReloadConfig> optReloadConfig = getReloadConfig(realm);
        if (!optReloadConfig.isPresent()) {
            return Optional.empty();
        }
        MetadataReloadConfig reloadConfig = optReloadConfig.get();

        MetadataUpdater updater = new MetadataUpdater(reloadConfig, new SAML2MetaManager());
        MetadataReloadAuditor auditor = InjectorHolder.getInstance(MetadataReloadAuditor.class);
        MetadataReloadTask task = new MetadataReloadTask(
                realm,
                reloadConfig.metadataMap(),
                updater,
                auditor);

        return Optional.of(task);
    }

    /**
     * Get <code>MetadataReloadConfig</code> instance given realm.
     *
     * @param realm
     * @return Optional <code>MetadataReloadConfig</code>. Return
     *         <code>null</code> if the service is not configured or invalid for
     *         given realm.
     * @throws SMSException If an error occurs while retrieving a service
     *                      configuration.
     * @throws SSOException If can't retrieve a service configuration for
     *                      the realm.
     */
    Optional<MetadataReloadConfig> getReloadConfig(final String realm)
            throws SMSException, SSOException {
        ServiceConfigManager scm = new ServiceConfigManager(
                AccessController.doPrivileged(AdminTokenAction.getInstance()),
                METADATA_RELOAD_SERVICE_NAME,
                SERVICE_VERSION);
        ServiceConfig config = scm.getOrganizationConfig(realm, null);
        if (config == null || !config.exists()) {
            DEBUG.message("Metadata auto reload is not configured in the realm {}.", realm);
            return Optional.empty();
        }
        Map options = config.getAttributes();

        Map<URL, Path> metadataMap = generateMetadataMap(options);

        String executeTimeStr = CollectionHelper.getMapAttr(options, EXECUTE_TIME);
        String executeServerURL = CollectionHelper.getMapAttr(options, EXECTE_SERVER_URL);
        String targetRoleStr = CollectionHelper.getMapAttr(options, TARGET_ROLE);
        if (executeTimeStr == null || targetRoleStr == null) {
            DEBUG.error("Required parameter is null.");
            return Optional.empty();
        }

        LocalTime executeTime;
        try {
            executeTime = LocalTime.parse(executeTimeStr);
        } catch (DateTimeParseException e) {
            DEBUG.error("Invalid datetime format.", e);
            return Optional.empty();
        }

        TargetRole targetRole;
        try {
            targetRole = TargetRole.valueOf(targetRoleStr);
        } catch (IllegalArgumentException e) {
            DEBUG.error("Invalid target role.", e);
            return Optional.empty();
        }

        Set<String> includeEntities = (Set<String>) options.get(INCLUDE_ENTITIES);
        Set<String> excludeEntities = (Set<String>) options.get(EXCLUDE_ENTITIES);
        boolean allowCreateEntities = CollectionHelper.getBooleanMapAttr(options, ALLOW_CREATE_ENTITIES, true);
        boolean checkExpirationDate = CollectionHelper.getBooleanMapAttr(options, CHECK_EXPIRATION_DATE, true);
        boolean validateSignature = CollectionHelper.getBooleanMapAttr(options, VALIDATE_SIGNATURE, true);

        MetadataReloadConfig reloadConfig = new MetadataReloadConfig(
                realm,
                metadataMap,
                executeTime,
                executeServerURL,
                targetRole,
                includeEntities,
                excludeEntities,
                allowCreateEntities,
                checkExpirationDate,
                validateSignature);

        return Optional.of(reloadConfig);
    }

    private Map<URL, Path> generateMetadataMap(Map options) {
        try {
            Set<String> tmp = CollectionHelper.getMapSetThrows(options, METADATA_URL_BACKUP_MAP);
            Map<String, String> metadataMapStr = MAP_VALUE_PARSER.parse(tmp);

            Map<URL, Path> metadataMap = new HashMap<>();
            for (String urlStr : metadataMapStr.keySet()) {
                String pathStr = metadataMapStr.get(urlStr);

                URL metadataURL;
                try {
                    metadataURL = new URL(urlStr);
                } catch (MalformedURLException e) {
                    DEBUG.error("Invalid metadata url.", e);
                    continue;
                }

                Path backupPath;
                try {
                    backupPath = Paths.get(pathStr);
                } catch (InvalidPathException e) {
                    DEBUG.error("Invalid backup path.", e);
                    continue;
                }

                metadataMap.put(metadataURL, backupPath);
            }
            return metadataMap;
        } catch (ValueNotFoundException e) {
            DEBUG.error("Invalid configuration.", e);
            return new HashMap<>();
        }
    }

}
