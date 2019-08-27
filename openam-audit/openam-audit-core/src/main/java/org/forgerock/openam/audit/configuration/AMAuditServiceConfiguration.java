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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2019 Open Source Solution Technology Corporation
 */
package org.forgerock.openam.audit.configuration;

import org.forgerock.audit.AuditServiceConfiguration;
import org.forgerock.openam.audit.AMAuditService;

import java.util.HashSet;
import java.util.Set;

/**
 * Audit service configuration specific to OpenAM. An instance of the current state can be retrieved from
 * {@link AuditServiceConfigurationProvider}. The instance retrieved from {@link AuditServiceConfigurationProvider}
 * will represent the current settings in the SMS.
 * <p/>
 * Each of the Audit Services has its own configuration, which is stored with the Audit Service and can be retrieved
 * in a thread-safe way via its own accessor methods -
 * {@link AMAuditService#isAuditEnabled(String, org.forgerock.openam.audit.AuditConstants.EventName)}.
 *
 * @since 13.0.0
 */
public class AMAuditServiceConfiguration extends AuditServiceConfiguration {

    private final Set<String> blacklistedEventNames;
    private final boolean auditEnabled;
    private final boolean ltzEnabled;

    /**
     * Create an instance of {@code AMAuditServiceConfiguration} with the specified values.
     *
     * @param auditEnabled Is audit logging enabled.
     */
    public AMAuditServiceConfiguration(boolean auditEnabled) {
        this.auditEnabled = auditEnabled;
        this.blacklistedEventNames = new HashSet<>();
        this.ltzEnabled = true;
    }

    /**
     * Create an instance of {@code AMAuditServiceConfiguration} with the specified values.
     *
     * @param auditEnabled Is audit logging enabled.
     * @param blacklistedEventNames A set of event names which we DO NOT want to audit.
     * @param ltzEnabled Is the local time zone og audit logging timestamp enabled.
     */
    public AMAuditServiceConfiguration(boolean auditEnabled, Set<String> blacklistedEventNames, boolean ltzEnabled) {

        this.auditEnabled = auditEnabled;
        this.blacklistedEventNames = blacklistedEventNames;
        this.ltzEnabled = ltzEnabled;
    }

    /**
     * Is audit logging enabled.
     * @return true if audit logging is enabled.
     */
    public boolean isAuditEnabled() {
        return auditEnabled;
    }

    /**
     * Is the specified event name blacklisted, i.e. one which we do NOT want to audit.  Passing in {@literal null}
     * turns the checking off, returning {@literal false}, such that no event name is blacklisted.
     *
     * @param eventName the specified event name as a string, or {@literal null}
     * @return true if blacklisted, i.e. we do NOT want to audit
     */
    public boolean isBlacklisted(String eventName) {
        if (eventName == null) {
            return false;
        }
        return blacklistedEventNames.contains(eventName.toString());
    }

    /**
     * Is audit logging enabled.
     * @return true if audit logging is enabled.
     */
    public boolean isLtzEnabled() {
        return ltzEnabled;
    }

}
