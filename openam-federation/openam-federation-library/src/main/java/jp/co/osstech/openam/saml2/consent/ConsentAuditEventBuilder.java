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
package jp.co.osstech.openam.saml2.consent;

import java.util.List;

import org.forgerock.audit.events.AuditEventBuilder;

/**
 * Builder for SAML2 attribute consent activity audit event.
 */
class ConsentAuditEventBuilder extends AuditEventBuilder<ConsentAuditEventBuilder> {

    private static final String REALM = "realm";
    private static final String IDP = "idp";
    private static final String SP = "sp";
    private static final String ATTRIBUTES = "attributes";
    private static final String CONSENT_TYPE = "consentType";
    private static final String USER_ID = "userId";

    ConsentAuditEventBuilder userID(String userID) {
        jsonValue.put(USER_ID, userID);
        return this;
    }

    ConsentAuditEventBuilder realm(String realm) {
        jsonValue.put(REALM, realm);
        return this;
    }

    ConsentAuditEventBuilder idp(String idp) {
        jsonValue.put(IDP, idp);
        return this;
    }

    ConsentAuditEventBuilder sp(String sp) {
        jsonValue.put(SP, sp);
        return this;
    }

    ConsentAuditEventBuilder attributes(List<String> attributes) {
        jsonValue.put(ATTRIBUTES, attributes);
        return this;
    }

    ConsentAuditEventBuilder consentType(String consentType) {
        jsonValue.put(CONSENT_TYPE, consentType);
        return this;
    }

}
