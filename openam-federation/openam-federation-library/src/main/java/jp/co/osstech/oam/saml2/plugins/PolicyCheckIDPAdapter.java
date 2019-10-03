/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2019 Open Source Solution Technology Corporation
 * All Rights Reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html 
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html 
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */

package jp.co.osstech.oam.saml2.plugins;

import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.util.AMAuthUtils;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.entitlement.Entitlement;
import com.sun.identity.entitlement.EntitlementException;
import com.sun.identity.entitlement.Evaluator;
import com.sun.identity.entitlement.opensso.SubjectUtils;
import com.sun.identity.federation.common.FSUtils;
import com.sun.identity.policy.interfaces.Condition;
import com.sun.identity.saml.common.SAMLUtils;
import com.sun.identity.saml2.plugins.SAML2IdentityProviderAdapter;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.profile.IDPCache;
import com.sun.identity.saml2.profile.IDPSSOUtil;
import com.sun.identity.saml2.profile.IDPSession;
import com.sun.identity.saml2.protocol.AuthnRequest;
import com.sun.identity.saml2.protocol.Response;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.configuration.SystemPropertiesManager;
import com.sun.identity.shared.encode.URLEncDec;
import com.sun.identity.sm.DNMapper;
import java.io.IOException;
import java.security.AccessController;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.forgerock.openam.utils.StringUtils;

/**
 * This class <code>PolicyCheckIDPAdapter</code> implements a SAML2 Identity Provider Adapter.
 */
public class PolicyCheckIDPAdapter implements SAML2IdentityProviderAdapter {
    
    private static final String INDEX = "index";
    private static final String ACS_URL = "acsURL";
    private static final String SP_ENTITY_ID = "spEntityID";
    private static final String IDP_ENTITY_ID = "idpEntityID";
    private static final String BINDING = "binding";
    private static final String POLICY_SET_NAME = "SAML2ProviderService";
    private static final String ACTION_NAME = "IssueAssertion";
    public static final String REALM_DN = "am.policy.realmDN";
    
    /**
     * Default Constructor.
     */
    public PolicyCheckIDPAdapter() {
    }

    /**
     * Default implementation, takes no action.
     */
    @Override
    public void initialize(String hostedEntityID, String realm) {
        // Do nothing
    }

    /**
     * Default implementation, takes no action and returns false (no interruption to processing).
     * @throws com.sun.identity.saml2.common.SAML2Exception
     */
    @Override
    public boolean preSingleSignOn(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            AuthnRequest authnRequest,
            String reqID) throws SAML2Exception {
        return false;
    }

    /**
     * Default implementation, takes no action and returns false (no interruption to processing).
     * @throws com.sun.identity.saml2.common.SAML2Exception
     */
    @Override
    public boolean preAuthentication(
            String hostedEntityID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            AuthnRequest authnRequest,
            Object session,
            String reqID,
            String relayState) throws SAML2Exception {
        return false;
    }

    /**
     * Check policy and if necessary redirect for additional authentication.
     * @throws com.sun.identity.saml2.common.SAML2Exception
     */
    @Override
    public boolean preSendResponse(
            AuthnRequest authnRequest,
            String hostProviderID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            Object session,
            String reqID,
            String relayState) throws SAML2Exception {
        
        final String classMethod = "preSendResponse:";
        final SSOToken token = (SSOToken)session;
        Map<String, Set<String>> env = new HashMap<>();
        
        if (realm == null || realm.length() == 0) {
            SAML2Utils.debug.error("{} realm was null or empty", classMethod);
            SAMLUtils.sendError(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "errorCode0", "Failed to evaluate provider policy");
            return true;
        }
        Set<String> set = new HashSet<>();
        set.add(DNMapper.orgNameToDN(realm));
        env.put(REALM_DN, set);
        
        final String spEntityID = authnRequest.getIssuer().getValue();
        if (spEntityID == null) {
            SAML2Utils.debug.error("{} Failed to get spEntityID from authnRequest", classMethod);
            SAMLUtils.sendError(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "errorCode1", "Failed to evaluate policy");
            return true;
        }
        String resourceString = String.format("%s=%s&%s=%s", IDP_ENTITY_ID, hostProviderID, SP_ENTITY_ID, spEntityID);

        List<Entitlement> entitlements;
        SSOToken adminSSOToken = (SSOToken) AccessController.doPrivileged(AdminTokenAction.getInstance());
            
        try {
            Evaluator evaluator = new Evaluator(SubjectUtils.createSubject(adminSSOToken), POLICY_SET_NAME);
            entitlements = evaluator.evaluate(realm, SubjectUtils.createSubject(token), resourceString, env, false);
        } catch (EntitlementException eex) {
            SAML2Utils.debug.error("{} Failed to evaluate policy {}", classMethod, eex.getMessage());
            SAMLUtils.sendError(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "errorCode2", "Failed to evaluate policy");
            return true;
        }       
        
        Entitlement result = entitlements.get(0);
        Boolean allowed = result.getActionValue(ACTION_NAME);
        
        if (allowed == null || !allowed) {
            if (result.hasAdvice()) {
                Map <String, Set<String>> advices = result.getAdvices();
                Set<String> advice;           
                String paramName = null;
                String realmQualifiedData = null;
                
                advice = advices.get(Condition.AUTH_LEVEL_CONDITION_ADVICE);
                if (advice != null && !advice.isEmpty()) {
                    paramName = ISAuthConstants.AUTH_LEVEL_PARAM;
                    realmQualifiedData = advice.iterator().next();
                }
                
                if (paramName == null) {
                    advice = advices.get(Condition.AUTH_SCHEME_CONDITION_ADVICE);
                    if (advice != null && !advice.isEmpty()) {
                        paramName = ISAuthConstants.MODULE_PARAM;
                        realmQualifiedData = advice.iterator().next();
                    }
                }

                if (paramName == null) {
                    advice = advices.get(Condition.AUTHENTICATE_TO_SERVICE_CONDITION_ADVICE);
                    if (advice != null && !advice.isEmpty()) {
                        paramName = ISAuthConstants.SERVICE_PARAM;
                        realmQualifiedData = advice.iterator().next();
                    }
                }
                
                String nvPair = null;
                if (paramName != null && realmQualifiedData != null) {
                    String adviceValue = AMAuthUtils.getDataFromRealmQualifiedData(realmQualifiedData);
                    nvPair = String.format("%s=%s", paramName, adviceValue);
                }

                if (nvPair != null) {
                    try {
                        redirectToAuth(request, response, authnRequest, realm, hostProviderID, reqID, nvPair);
                        String sessionIndex = IDPSSOUtil.getSessionIndex(token);
                        if (sessionIndex != null && sessionIndex.length() != 0) {
                            IDPSession oldIDPSession = IDPCache.idpSessionsByIndices.get(sessionIndex);
                            if (oldIDPSession != null) {
                                IDPCache.oldIDPSessionCache.put(reqID, oldIDPSession);
                            } else {
                                SAML2Utils.debug.error(classMethod + "The old SAML2 session was not found in the idp session " +
                                    "by indices cache");
                            }
                        }
                        IDPCache.isSessionUpgradeCache.add(reqID);
                    } catch (SAML2Exception | IOException | ServletException ex) {
                        SAML2Utils.debug.error("{} Failed to redirect to Auth {}", classMethod, ex.getMessage());
                            SAMLUtils.sendError(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                                    "errorCode3", "Failed to evaluate policy");
                    }
                    return true;
                }
            }

            SAML2Utils.debug.warning("{} Policy denied the access", classMethod);
            SAMLUtils.sendError(request, response, HttpServletResponse.SC_FORBIDDEN,
                "errorCode4", "SAML endpoint protected by policy");
            return true;
        }
        return false;
    }
    
    private static void redirectToAuth(HttpServletRequest request,
            HttpServletResponse response, AuthnRequest authnRequest, String realm,
            String hostProviderID, String reqID, String nvPair) 
            throws SAML2Exception, IOException, ServletException {
        
        final String classMethod = "redirectToAuth:";
        String rootUrl;
        
        String authService = IDPSSOUtil.getAuthenticationServiceURL(realm, hostProviderID, request);
        rootUrl = request.getScheme() + "://" + request.getServerName() 
                + ":" + request.getServerPort() + request.getContextPath();
        boolean forward;
        StringBuffer authURL;

        if (FSUtils.isSameContainer(request, authService)) { // Forward
            forward = true;
            String relativePath = authService.substring(rootUrl.length());
            authURL = new StringBuffer(relativePath).append("&forward=true");
        } else { // Redirect
            forward = false;
            authURL = new StringBuffer(authService);
        }
        
        String spEntityID = authnRequest.getIssuer().getValue();

        if (authURL.indexOf("?") == -1) {
            authURL.append("?");
        } else {
            authURL.append("&");
        }
        authURL.append(SAML2Constants.SPENTITYID).append("=").append(URLEncDec.encode(spEntityID));
        authURL.append("&").append(nvPair).append("&ForceAuth=true&goto=");

        StringBuffer gotoURL;
        if (forward) {  // Forward needs a relative URL
            gotoURL = new StringBuffer(request.getRequestURI().substring(request.getContextPath().length()));
        } else {  // Redirect needs an absolute URL
            String rpUrl = IDPSSOUtil.getAttributeValueFromIDPSSOConfig(realm, hostProviderID, SAML2Constants.RP_URL);
            if (StringUtils.isNotEmpty(rpUrl)) {
                gotoURL = new StringBuffer(rpUrl);
                gotoURL.append(request.getRequestURI().substring(request.getContextPath().length()));
            } else {
                gotoURL = request.getRequestURL();
            }
        }

        /** Just in case that the original authnRequest get lost.
         * 
         *  Adding these extra parameters will ensure that we can send back SAML error response to the SP even when the
         *  originally received AuthnRequest gets lost.
         */

        gotoURL.append("?ReqID=").append(reqID).append('&')
                .append(INDEX).append('=').append(authnRequest.getAssertionConsumerServiceIndex()).append('&')
                .append(ACS_URL).append('=').append(URLEncDec.encode(authnRequest.getAssertionConsumerServiceURL())).append('&')
                .append(SP_ENTITY_ID).append('=').append(URLEncDec.encode(authnRequest.getIssuer().getValue())).append('&')
                .append(BINDING).append('=').append(URLEncDec.encode(authnRequest.getProtocolBinding()));

        authURL.append(URLEncDec.encode(gotoURL.toString()));
        SAML2Utils.debug.message("{} New URL for authentication: {}", classMethod, authURL.toString());

        if (forward) { // In the same container 
            authURL.append('&').append(SystemPropertiesManager.get(Constants.AM_AUTH_COOKIE_NAME, "AMAuthCookie"));
            authURL.append('=');

            SAML2Utils.debug.message("{} Forward to ", classMethod, authURL.toString());
            request.setAttribute(Constants.FORWARD_PARAM, Constants.FORWARD_YES_VALUE);
            request.getRequestDispatcher(authURL.toString()).forward(request, response);        
        } else {  // Seperate container
            response.sendRedirect(authURL.toString());
        }
    }
    
    /**
     * Default implementation, takes no action.
     * @throws com.sun.identity.saml2.common.SAML2Exception
     */
    @Override
    public void preSendFailureResponse(
            HttpServletRequest request,
            HttpServletResponse response,
            String faultCode,
            String faultDetail) throws SAML2Exception {
        // Do nothing
    }

    @Override
    public void preSignResponse(AuthnRequest authnRequest, Response res, String hostProviderID, String realm,
        HttpServletRequest request, Object session, String relayState) throws SAML2Exception {
        // Do nothing
    }

}
