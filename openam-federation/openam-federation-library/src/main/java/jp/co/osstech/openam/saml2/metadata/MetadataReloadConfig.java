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

import java.net.URL;
import java.nio.file.Path;
import java.time.LocalTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * The class <code>MetadataReloadConfig</code> represents the configuration of
 * SAML metadata auto reload service for the specific realm.
 */
class MetadataReloadConfig {

    private String realm;
    private Map<URL, Path> metadataMap;
    private LocalTime executeTime;
    private String executeServerURL;
    private TargetRole target;
    private Set<String> includeEntities;
    private Set<String> excludeEntities;
    private boolean allowCreateEntities;
    private boolean checkExpirationDate;
    private boolean validateSignature;

    /**
     * Constructor
     *
     * @param realm               Realm.
     * @param metadataMap         Map of URLs and paths. The keys are URL of the
     *                            metadata and the values are path to backup file.
     * @param executeTime         When reload the metadata.
     * @param executeServerURL    Server URL which reload the metadata
     * @param target              Target role.
     * @param includeEntities     Set of entity ID always included.
     * @param excludeEntities     Set of entity ID always excluded.
     * @param allowCreateEntities Whether allow to create new entities.
     * @param checkExpirationDate Whether check the expiration of the metadata.
     * @param validateSignature   Whether validate the signature of the metadata.
     */
    MetadataReloadConfig(String realm, Map<URL, Path> metadataMap, LocalTime executeTime,
            String executeServerURL, TargetRole target, Set<String> includeEntities, Set<String> excludeEntities,
            boolean allowCreateEntities, boolean checkExpirationDate, boolean validateSignature) {
        this.realm = realm;
        this.metadataMap = Collections.unmodifiableMap(metadataMap);
        this.executeTime = executeTime;
        this.executeServerURL = executeServerURL;
        this.target = target;
        this.includeEntities = Collections.unmodifiableSet(includeEntities);
        this.excludeEntities = Collections.unmodifiableSet(excludeEntities);
        this.allowCreateEntities = allowCreateEntities;
        this.checkExpirationDate = checkExpirationDate;
        this.validateSignature = validateSignature;
    }

    String realm() {
        return realm;
    }

    Map<URL, Path> metadataMap() {
        return new HashMap<>(metadataMap);
    }

    LocalTime executeTime() {
        return executeTime;
    }

    String executeServerURL() {
        return executeServerURL;
    }

    TargetRole targetRole() {
        return target;
    }

    Set<String> includeEntities() {
        return includeEntities;
    }

    Set<String> excludeEntities() {
        return excludeEntities;
    }

    boolean allowCreateEntities() {
        return allowCreateEntities;
    }

    boolean shouldCheckExpirationDate() {
        return checkExpirationDate;
    }

    boolean shouldValidateSignature() {
        return validateSignature;
    }

    enum TargetRole {
        ALL,
        SP_ONLY,
        IDP_ONLY,
        NOTHING
    }

}
