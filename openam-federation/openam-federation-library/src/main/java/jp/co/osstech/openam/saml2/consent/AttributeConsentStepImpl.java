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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.forgerock.openam.saml2.IDPSSOFederateRequest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.plugin.session.SessionException;
import com.sun.identity.plugin.session.SessionManager;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.plugins.IDPAttributeMapper;
import com.sun.identity.saml2.profile.CacheObject;
import com.sun.identity.saml2.profile.IDPCache;
import com.sun.identity.shared.debug.Debug;

import jp.co.osstech.openam.saml2.consent.AttributeConsent.ConsentType;

/**
 * The <code>AttributeConsentStep</code> implementation that works when SAML2 attribute
 * release consent function is enabled.
 */
public class AttributeConsentStepImpl implements AttributeConsentStep {
    private static final Debug DEBUG = Debug.getInstance("SAML2AttributeConsent");

    private static final String CONSENT_PAGE_WITHOUT_CONTEXT_PATH = "/saml2/consent/";
    private static final String REQUEST_PARAM_CONSENT_ID = "consentID";

    private String realm;
    private String idpEntityId;
    private String spEntityId;
    private IDPAttributeMapper mapper;
    private IDPAttributeConsentConfig config;
    private AttributeConsentHistorySerializer serializer;
    private ConsentAuditor auditor;

    /**
     * Constructor.
     *
     * @param realm the realm
     * @param idpEntityId identity provider's entity ID
     * @param spEntityId service provider's entity ID
     * @param mapper the attribute mapper
     * @param config the configuration for consent
     * @param serializer the serializer that serialize encrypted consent history
     * @param auditor auditor for consent
     */
    public AttributeConsentStepImpl(
            String realm,
            String idpEntityId,
            String spEntityId,
            IDPAttributeMapper mapper,
            IDPAttributeConsentConfig config,
            AttributeConsentHistorySerializer serializer,
            ConsentAuditor auditor) {
        this.realm = realm;
        this.idpEntityId = idpEntityId;
        this.spEntityId = spEntityId;
        this.mapper = mapper;
        this.config = config;
        this.serializer = serializer;
        this.auditor = auditor;
    }

    @Override
    public boolean needRedirectToConsentPage(IDPSSOFederateRequest data, HttpServletRequest request)
            throws SAML2Exception, SSOException {
        SSOToken ssoToken = (SSOToken) data.getSession();
        return needRedirectToConsentPage(ssoToken, request);
    }

    @Override
    public boolean needRedirectToConsentPage(HttpServletRequest request) throws SAML2Exception, SSOException {
        SSOToken ssoToken;
        try {
            ssoToken = (SSOToken) SessionManager.getProvider().getSession(request);
        } catch (SessionException e) {
            ssoToken = null;
        }
        return needRedirectToConsentPage(ssoToken, request);
    }

    private boolean needRedirectToConsentPage(SSOToken ssoToken, HttpServletRequest request)
            throws SAML2Exception, SSOException {
        String consentId = request.getParameter(REQUEST_PARAM_CONSENT_ID);
        if (alreadyAgreed(ssoToken, consentId)) {
            return false;
        }

        if (!someAttributesRequireConsent(ssoToken)) {
            return false;
        }
        if (forceConsent(request)) {
            DEBUG.message("forceConsent parameter is set.");
            return true;
        }
        return true;
    }

    @Override
    public boolean requireConsent(SSOToken ssoToken, String consentID, String encryptedHistory)
            throws SAML2Exception, SSOException, IdRepoException {
        if (alreadyAgreed(ssoToken, consentID)) {
            return false;
        }
        if (!someAttributesRequireConsent(ssoToken)) {
            return false;
        }
        if (!historyRequireConsent(ssoToken, encryptedHistory)) {
            return false;
        }
        return true;
    }

    @Override
    public boolean showConsentCheckbox() {
        return true;
    }

    @Override
    public void redirectToConsentPage(
            IDPSSOFederateRequest data,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException, SessionException, SSOException {
        String contextPath = request.getContextPath();
        String consentID = request.getParameter(REQUEST_PARAM_CONSENT_ID);
        if (consentID == null) {
            consentID = generateConsentID();
        }
        String originalRequestURI = request.getRequestURI() + "?" + request.getQueryString();
        SSOToken ssoToken = (SSOToken) SessionManager.getProvider().getSession(request);

        AttributeConsentCache cache = new AttributeConsentCache(realm, idpEntityId, spEntityId,
                ssoToken.getPrincipal().getName());
        IDPCache.attributeConsentCache.put(consentID, new CacheObject(cache));

        StringBuilder builder = new StringBuilder()
                .append(contextPath)
                .append(CONSENT_PAGE_WITHOUT_CONTEXT_PATH)
                .append("?")
                .append("realm=")
                .append(realm)
                .append("&idpEntityId=")
                .append(idpEntityId)
                .append("&spEntityId=")
                .append(spEntityId)
                .append("&").append(REQUEST_PARAM_CONSENT_ID).append("=")
                .append(consentID)
                .append("&originalRequestURI=")
                .append(URLEncoder.encode(originalRequestURI, "UTF-8"));

        if (forceConsent(request)) {
            builder.append("&").append(REQUEST_PARAM_FORCE_CONSENT).append("=true");
        }

        String destination = builder.toString();
        response.sendRedirect(destination);
    }

    @Override
    public List<ConsentRequiredAttribute> getConsentRequiredAttributes(SSOToken ssoToken, Locale locale)
            throws SAML2Exception {
        Map<String, List<String>> releasedAttribute = getReleasedAttributes(ssoToken);
        return config.getConsentRequiredAttributes(releasedAttribute, locale);
    }

    private boolean alreadyAgreed(SSOToken ssoToken, String consentID) throws SSOException {
        if (ssoToken == null || consentID == null) {
            return false;
        }
        AttributeConsentCache consentCache = getValidConsentCache(ssoToken, consentID);
        if (consentCache == null) {
            return false;
        }
        return consentCache.isAgreed();
    }

    private boolean someAttributesRequireConsent(SSOToken ssoToken) throws SAML2Exception {
        Map<String, List<String>> releasedAttributes = getReleasedAttributes(ssoToken);

        for (String attributeName : releasedAttributes.keySet()) {
            if (config.consentRequired(attributeName)) {
                return true;
            }
        }

        return false;
    }

    private boolean forceConsent(HttpServletRequest request) {
        return Boolean.valueOf(request.getParameter(REQUEST_PARAM_FORCE_CONSENT));
    }

    private boolean historyRequireConsent(SSOToken ssoToken, String encryptedHistory)
            throws SAML2Exception, SSOException, IdRepoException {
        AttributeConsentHistory history = serializer.decryptAndDeserialize(encryptedHistory);
        Map<String, List<String>> releasedAttributes = getReleasedAttributes(ssoToken);
        Set<String> consentRequiredAttributeNames = new HashSet<>();
        for (String attributeName : releasedAttributes.keySet()) {
            if (config.consentRequired(attributeName)) {
                consentRequiredAttributeNames.add(attributeName);
            }
        }
        return history.consentRequired(realm, idpEntityId, spEntityId, getUserName(ssoToken),
                consentRequiredAttributeNames);
    }

    private Map<String, List<String>> getReleasedAttributes(SSOToken ssotoken) throws SAML2Exception {
        Map<String, List<String>> releasedAttributes = new HashMap<>();

        List attributes = mapper.getAttributes(ssotoken, idpEntityId, spEntityId, realm);
        if (attributes == null) {
            return releasedAttributes;
        }

        for (Object obj : attributes) {
            Attribute attribute = (Attribute) obj;
            String attributeName = attribute.getName();
            List<String> attributeValue = (List<String>) attribute.getAttributeValueString();
            releasedAttributes.put(attributeName, attributeValue);
        }

        return releasedAttributes;
    }

    @Override
    public String agree(SSOToken ssoToken, String encryptedHistoy, List<String> agreedAttributes,
            ConsentType type, String consentID)
            throws JsonProcessingException, SSOException, IdRepoException, SAML2Exception {
        AttributeConsentCache consentCache = getValidConsentCache(ssoToken, consentID);
        if (consentCache == null) {
            throw new SAML2Exception("Invalid consent ID");
        }

        consentCache.agree();

        auditor.auditAgree(ssoToken, realm, idpEntityId, spEntityId, agreedAttributes, type);
        AttributeConsentHistory history = serializer.decryptAndDeserialize(encryptedHistoy);
        history.update(realm, idpEntityId, spEntityId, getUserName(ssoToken), new HashSet<>(agreedAttributes), type);
        String newHistoryEncrypted = serializer.serializeAndEncrypt(history);

        return newHistoryEncrypted;
    }

    @Override
    public void reject(SSOToken ssoToken, List<String> attributes) {
        auditor.auditReject(ssoToken, realm, idpEntityId, spEntityId, attributes);
    }

    private static String getUserName(SSOToken ssoToken) throws SSOException, IdRepoException {
        return new AMIdentity(ssoToken).getName();
    }

    private String generateConsentID() {
        return UUID.randomUUID().toString();
    }

    @Override
    public AttributeConsentCache getValidConsentCache(SSOToken ssoToken, String consentID)
            throws SSOException {
        CacheObject cache = (CacheObject) IDPCache.attributeConsentCache.get(consentID);
        if (cache == null) {
            return null;
        }
        AttributeConsentCache consentCache = (AttributeConsentCache) cache.getObject();
        boolean valid = consentCache.getRealm().equals(realm)
                && consentCache.getIdpEntityId().equals(idpEntityId)
                && consentCache.getSpEntityId().equals(spEntityId)
                && consentCache.getUserDN().equals(ssoToken.getPrincipal().getName());
        if (!valid) {
            return null;
        }
        return consentCache;
    }
}
