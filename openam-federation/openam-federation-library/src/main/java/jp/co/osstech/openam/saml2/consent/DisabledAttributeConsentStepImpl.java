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

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.forgerock.openam.saml2.IDPSSOFederateRequest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.plugin.session.SessionException;
import com.sun.identity.saml2.common.SAML2Exception;

import jp.co.osstech.openam.saml2.consent.AttributeConsent.ConsentType;

/**
 * The <code>AttributeConsentStep</code> implementation that works when SAML2 attribute
 * release consent function is disabled.
 */
public class DisabledAttributeConsentStepImpl implements AttributeConsentStep {

    @Override
    public boolean needRedirectToConsentPage(IDPSSOFederateRequest data, HttpServletRequest request)
            throws SAML2Exception, SSOException {
        return false;
    }

    @Override
    public boolean needRedirectToConsentPage(HttpServletRequest request)
            throws SAML2Exception, SSOException {
        return false;
    }

    @Override
    public boolean requireConsent(SSOToken ssoToken, String consentID, String encryptedHistory)
            throws SAML2Exception, SSOException, IdRepoException {
        return false;
    }

    @Override
    public boolean showConsentCheckbox() {
        return false;
    }

    @Override
    public void redirectToConsentPage(IDPSSOFederateRequest data, HttpServletRequest request,
            HttpServletResponse response) throws IOException, SessionException, SSOException {
    }

    @Override
    public List<ConsentRequiredAttribute> getConsentRequiredAttributes(SSOToken ssoToken, Locale locale)
            throws SAML2Exception {
        return Collections.emptyList();
    }

    @Override
    public String agree(SSOToken ssoToken, String encryptedHistoy, List<String> agreedAttributes, ConsentType type,
            String consentID) throws JsonProcessingException, SSOException, IdRepoException, SAML2Exception {
        return encryptedHistoy;
    }

    @Override
    public void reject(SSOToken ssoToken, List<String> attributes) {
    }

    @Override
    public AttributeConsentCache getValidConsentCache(SSOToken ssoToken, String consentID) throws SSOException {
        return null;
    }

}
