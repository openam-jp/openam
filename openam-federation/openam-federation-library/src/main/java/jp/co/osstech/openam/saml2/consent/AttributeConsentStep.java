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
 * The interface <code>AttributeConsentStep</code> handles SAML2 attributes consent
 * step.
 */
public interface AttributeConsentStep {

    public static final String REQUEST_PARAM_FORCE_CONSENT = "forceConsent";

    /**
     * Determines whether to redirect the user to the consent page.
     * This method is called in case of SP-Init.
     *
     * @param data the data for SP-Init SSO
     * @param request the <code>HttpServletRequest</code> object
     * @return true if consent required
     * @throws SAML2Exception
     * @throws SSOException
     */
    public boolean needRedirectToConsentPage(IDPSSOFederateRequest data, HttpServletRequest request)
            throws SAML2Exception, SSOException;

    /**
     * Determines whether to redirect the user to the consent page.
     * This method is called in case of IdP-Init.
     *
     * @param request the <code>HttpServletRequest</code> object
     * @return true if consent required
     * @throws SAML2Exception
     * @throws SSOException
     */
    public boolean needRedirectToConsentPage(HttpServletRequest request)
            throws SAML2Exception, SSOException;

    /**
     * Determines whether consent is required.
     *
     * @param ssoToken user's sso token
     * @param consentID consent ID
     * @param encryptedHistory encrypted consent history
     * @return true if consent required. Returns false if consent has already been given or
     * consent is not required for the target attributes.
     * @throws SAML2Exception
     * @throws SSOException
     * @throws IdRepoException
     */
    public boolean requireConsent(SSOToken ssoToken, String consentID, String encryptedHistory)
            throws SAML2Exception, SSOException, IdRepoException;

    /**
     * Determines whether to ask the user to show the consent page.
     *
     * @return true if SAML2 attribute release consent function is enabled
     */
    public boolean showConsentCheckbox();

    /**
     * Redirects to consent page.
     *
     * @param data the data for SP-Init SSO
     * @param request the <code>HttpServletRequest</code> object
     * @param response the <code>HttpServletResponse</code> object
     * @throws IOException
     * @throws SessionException
     * @throws SSOException
     */
    public void redirectToConsentPage(IDPSSOFederateRequest data, HttpServletRequest request,
            HttpServletResponse response)
            throws IOException, SessionException, SSOException;

    /**
     * Gets Attributes that requires consent.
     *
     * @param ssoToken user's sso token
     * @param locale Locale of the Request
     * @return attributes that requires consent
     * @throws SAML2Exception
     */
    public List<ConsentRequiredAttribute> getConsentRequiredAttributes(SSOToken ssoToken, Locale locale)
            throws SAML2Exception;

    /**
     * Agrees to release attributes.
     *
     * @param ssoToken user's sso token
     * @param encryptedHistoy encrypted consent history
     * @param agreedAttributes agreed attributes
     * @param type consent type
     * @param consentID consent ID
     * @return new encrypted consent history
     * @throws JsonProcessingException
     * @throws SSOException
     * @throws IdRepoException
     * @throws SAML2Exception
     */
    public String agree(SSOToken ssoToken, String encryptedHistoy, List<String> agreedAttributes,
            ConsentType type, String consentID)
            throws JsonProcessingException, SSOException, IdRepoException, SAML2Exception;

    /**
     * Rejects to release attributes.
     *
     * @param ssoToken user's sso token
     * @param attributes target attributes
     */
    public void reject(SSOToken ssoToken, List<String> attributes);

    /**
     * Get the validated <code>AttributeConsentCache</code> instance by given
     * consentID.
     *
     * @param ssoToken  user's sso token
     * @param consentID consent ID
     * @return <code>AttributeConsentCache</code> instance. Return null if the cache
     *         doesn't contain <code>AttributeConsentCache</code> instance
     *         corresponding to given consent ID or found instance doesn't match to
     *         current consent step.
     * @throws SSOException
     */
    public AttributeConsentCache getValidConsentCache(SSOToken ssoToken, String consentID)
            throws SSOException;
}
