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

/**
 * The class <code>AttributeConsentCache</code> is an object stored in the server
 * to retrieve informations about current SAML2 attribute consent step.
 */
public class AttributeConsentCache {
    private String realm;
    private String idpEntityId;
    private String spEntityId;
    private String userDN;
    private boolean agreed;

    AttributeConsentCache(String realm, String idpEntityId, String spEntityId, String userDN) {
        this.realm = realm;
        this.idpEntityId = idpEntityId;
        this.spEntityId = spEntityId;
        this.userDN = userDN;
        this.agreed = false;
    }

    public void agree() {
        agreed = true;
    }

    public String getRealm() {
        return realm;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public boolean isAgreed() {
        return agreed;
    }

    public String getUserDN() {
        return userDN;
    }

}
