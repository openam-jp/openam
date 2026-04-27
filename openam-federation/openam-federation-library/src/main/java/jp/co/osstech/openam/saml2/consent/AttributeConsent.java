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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * The class <code>AttributeConsent</code> holds informations about an attribute
 * release consent.
 */
public class AttributeConsent {

    private String realm;
    private String idpEntityId;
    private String spEntityId;
    private String userName;
    private Set<String> agreedAttributes;
    private ConsentType consentType;

    /**
     * This default constructor is only used for deserializing by
     * <code>ObjectMapper</code>.
     */
    AttributeConsent() {

    }

    public AttributeConsent(String realm, String idpEntityId, String spEntityId, String userName,
            Set<String> agreedAttributes,
            ConsentType consentType) {
        this.realm = realm;
        this.idpEntityId = idpEntityId;
        this.spEntityId = spEntityId;
        this.userName = userName;
        this.agreedAttributes = Collections.unmodifiableSet(agreedAttributes);
        this.consentType = consentType;
    }

    String getRealm() {
        return realm;
    }

    String getIdpEntityId() {
        return idpEntityId;
    }

    String getSpEntityId() {
        return spEntityId;
    }

    String getUserName() {
        return userName;
    }

    Set<String> getAgreedAttributes() {
        return new HashSet<>(agreedAttributes);
    }

    ConsentType getConsentType() {
        return consentType;
    }

    public enum ConsentType {
        ASK_AGAIN,
        ASK_IF_CHANGE,
        ASK_NEVER
    }
}
