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
* Portions Copyrighted 2017 Open Source Solution Technology Corporation.
*/
package org.forgerock.openam.saml2;

import com.sun.identity.multiprotocol.MultiProtocolUtils;
import com.sun.identity.multiprotocol.SingleLogoutManager;
import com.sun.identity.plugin.monitoring.FedMonAgent;
import com.sun.identity.plugin.monitoring.FedMonSAML2Svc;
import com.sun.identity.plugin.monitoring.MonitorManager;
import com.sun.identity.plugin.session.SessionException;
import com.sun.identity.plugin.session.SessionManager;
import com.sun.identity.plugin.session.SessionProvider;
import com.sun.identity.saml2.assertion.AuthnContext;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.logging.LogUtil;
import com.sun.identity.saml2.plugins.IDPAuthnContextInfo;
import com.sun.identity.saml2.plugins.IDPAuthnContextMapper;
import com.sun.identity.saml2.profile.CacheObject;
import com.sun.identity.saml2.profile.ClientFaultException;
import com.sun.identity.saml2.profile.IDPCache;
import com.sun.identity.saml2.profile.IDPSSOUtil;
import com.sun.identity.saml2.profile.IDPSession;
import com.sun.identity.saml2.profile.ServerFaultException;
import com.sun.identity.saml2.protocol.AuthnRequest;
import com.sun.identity.saml2.protocol.NameIDPolicy;
import com.sun.identity.saml2.protocol.Response;
import org.forgerock.openam.audit.AMAuditEventBuilderUtils;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.logging.Level;

/**
 * An implementation of A SAMLAuthenticatorLookup that uses the Util classes to make the federation connection.
 */
public class UtilProxySAMLAuthenticatorLookup extends SAMLBase implements SAMLAuthenticatorLookup {

    private final HttpServletRequest request;
    private final HttpServletResponse response;

    private final IDPSSOFederateRequest data;
    private final PrintWriter out;

    /**
     * Creates a new UtilProxySAMLAuthenticatorLookup
     *
     * @param data the details of the federation request.
     * @param request the Http request object.
     * @param response the http response object.
     * @param out the output.
     */
    public UtilProxySAMLAuthenticatorLookup(final IDPSSOFederateRequest data,
                                            final HttpServletRequest request,
                                            final HttpServletResponse response,
                                            final PrintWriter out) {
        this.data = data;
        this.out = out;
        this.request = request;
        this.response = response;
    }

    @Override
    public void retrieveAuthenticationFromCache() throws SessionException, ServerFaultException, ClientFaultException {

        final String classMethod = "UtilProxySAMLAuthenticatorLookup.retrieveAuthenticationFromCache: ";

        // the second visit, the user has already authenticated
        // retrieve the cache authn request and relay state

        // We need the session to pass it to the IDP Adapter preSendResponse
        SessionProvider sessionProvider = SessionManager.getProvider();
        try {
            data.setSession(sessionProvider.getSession(request));
            data.getEventAuditor().setSSOTokenId(data.getSession());
        } catch (SessionException se) {
            SAML2Utils.debug.error("An error occurred while retrieving the session: " + se.getMessage());
            data.setSession(null);
        }

        // Get the cached Authentication Request and Relay State before
        // invoking the IDP Adapter
        CacheObject cacheObj;
        synchronized (IDPCache.authnRequestCache) {
            cacheObj = (CacheObject) IDPCache.authnRequestCache.get(data.getRequestID());
        }
        if (cacheObj != null) {
            data.setAuthnRequest((AuthnRequest) cacheObj.getObject());
        }

        data.setRelayState((String) IDPCache.relayStateCache.get(data.getRequestID()));

        if (!isSessionValid(sessionProvider)) {
            return;
        }

        // Invoke the IDP Adapter after the user has been authenticated
        if (preSendResponse(request, response, data)) {
            return;
        }
        // End of block for IDP Adapter invocation

        synchronized (IDPCache.authnRequestCache) {
            cacheObj = (CacheObject) IDPCache.authnRequestCache.remove(data.getRequestID());
        }

        if (cacheObj != null) {
            data.setAuthnRequest((AuthnRequest) cacheObj.getObject());
        }

        synchronized (IDPCache.idpAuthnContextCache) {
            cacheObj = (CacheObject) IDPCache.idpAuthnContextCache.remove(data.getRequestID());
        }

        if (cacheObj != null) {
            data.setMatchingAuthnContext((AuthnContext) cacheObj.getObject());
        }

        data.setRelayState((String) IDPCache.relayStateCache.remove(data.getRequestID()));
        if (data.getAuthnRequest() == null) {
            authNotAvailable();
            return;
        }

        SAML2Utils.debug.message("{} RequestID= {}", classMethod, data.getRequestID());
        
        // Fix for Session Upgrade Bypass
        IDPAuthnContextMapper idpAuthnContextMapper = null;
        try {
            idpAuthnContextMapper = IDPSSOUtil.getIDPAuthnContextMapper(data.getRealm(), data.getIdpEntityID());
        } catch (SAML2Exception sme) {
            SAML2Utils.debug.error(classMethod, sme);
        }
        if (idpAuthnContextMapper == null) {
            SAML2Utils.debug.error(classMethod + "Unable to get IDPAuthnContextMapper from meta.");
            throw new ServerFaultException(data.getIdpAdapter(), METADATA_ERROR);
        }
        
        IDPAuthnContextInfo idpAuthnContextInfo = null;
        try {
            idpAuthnContextInfo = idpAuthnContextMapper.getIDPAuthnContextInfo(data.getAuthnRequest(),
                    data.getIdpEntityID(), data.getRealm());
        } catch (SAML2Exception sme) {
            SAML2Utils.debug.error(classMethod, sme);
        }

        if (idpAuthnContextInfo == null) {
            SAML2Utils.debug.message("{} Unable to find valid AuthnContext. Sending error Response.", classMethod);
            try {
                Response res = SAML2Utils.getErrorResponse(data.getAuthnRequest(), SAML2Constants.REQUESTER,
                        SAML2Constants.NO_AUTHN_CONTEXT, null, data.getIdpEntityID());
                StringBuffer returnedBinding = new StringBuffer();
                String acsURL = IDPSSOUtil.getACSurl(data.getSpEntityID(), data.getRealm(),
                        data.getAuthnRequest(), request, returnedBinding);
                String acsBinding = returnedBinding.toString();
                IDPSSOUtil.sendResponse(request, response, out, acsBinding, data.getSpEntityID(), data.getIdpEntityID(), data.getIdpMetaAlias(), data.getRealm(),
                        data.getRelayState(), acsURL, res, data.getSession());
            } catch (SAML2Exception sme) {
                SAML2Utils.debug.error(classMethod, sme);
                throw new ServerFaultException(data.getIdpAdapter(), METADATA_ERROR);
            }
            return;
        }

        /** 
         * Since Session Upgrade has been done at this stage, #isSessionUpgrade() should return false,
         * if not, it implies a possible security breach.
         */
        boolean upgradeNeeded;
        upgradeNeeded = isSessionUpgrade(idpAuthnContextInfo, data.getSession());
        if (upgradeNeeded) {
            throw new SessionException("Session upgrade was skipped: Possible attempt to compromise security.");
        }
        // End of Fix

        boolean isSessionUpgrade = false;

        if (CollectionUtils.isNotEmpty(IDPCache.isSessionUpgradeCache)) {
            isSessionUpgrade = IDPCache.isSessionUpgradeCache.contains(data.getRequestID());
        }

        if (isSessionUpgrade) {
            IDPSession oldSess = (IDPSession) IDPCache.oldIDPSessionCache.remove(data.getRequestID());
            String sessionIndex = IDPSSOUtil.getSessionIndex(data.getSession());
            if (StringUtils.isNotEmpty(sessionIndex)) {
                IDPCache.idpSessionsByIndices.put(sessionIndex, oldSess);

                final FedMonAgent agent = MonitorManager.getAgent();
                if (agent != null && agent.isRunning()) {
                    final FedMonSAML2Svc saml2Svc = MonitorManager.getSAML2Svc();
                    if (saml2Svc != null) {
                        saml2Svc.setIdpSessionCount(IDPCache.idpSessionsByIndices.size());
                    }
                }
            }
        }

        if (data.getSession() != null) {
            // call multi-federation protocol to set the protocol
            MultiProtocolUtils.addFederationProtocol(data.getSession(), SingleLogoutManager.SAML2);
        }

        // generate assertion response
        data.setSpEntityID(data.getAuthnRequest().getIssuer().getValue());
        NameIDPolicy policy = data.getAuthnRequest().getNameIDPolicy();
        String nameIDFormat = (policy == null) ? null : policy.getFormat();
        try {
            IDPSSOUtil.sendResponseToACS(request, response, out, data.getSession(), data.getAuthnRequest(),
                    data.getSpEntityID(), data.getIdpEntityID(), data.getIdpMetaAlias(), data.getRealm(), nameIDFormat,
                    data.getRelayState(), data.getMatchingAuthnContext());
        } catch (SAML2Exception se) {
            SAML2Utils.debug.error(classMethod + "Unable to do sso or federation.", se);
            throw new ServerFaultException(data.getIdpAdapter(), SSO_OR_FEDERATION_ERROR, se.getMessage());
        }

    }

    private void authNotAvailable() throws ServerFaultException {
        final String classMethod = "UtilProxySAMLAuthenticatorLookup.authNotavailable";

        //handle the case when the authn request is no longer available in the local cache. This could
        //happen for multiple reasons:
        //   - the SAML response has been already sent back for this request (e.g. browser back button)
        //   - the second visit reached a different OpenAM server, than the first and SAML SFO is disabled
        //   - the cache interval has passed
        SAML2Utils.debug.error(classMethod + "Unable to get AuthnRequest from cache, sending error response");
        try {
            SAML2Utils.debug.message("Invoking IDP adapter preSendFailureResponse hook");
            try {
                data.getIdpAdapter().preSendFailureResponse(request, response, SAML2Constants.SERVER_FAULT,
                        "UnableToGetAuthnReq");
            } catch (SAML2Exception se2) {
                SAML2Utils.debug.error("Error invoking the IDP Adapter", se2);
            }
            Response res = SAML2Utils.getErrorResponse(null, SAML2Constants.RESPONDER, null, null,
                    data.getIdpEntityID());
            res.setInResponseTo(data.getRequestID());
            StringBuffer returnedBinding = new StringBuffer();
            String spEntityID = request.getParameter(SP_ENTITY_ID);
            String acsURL = request.getParameter(ACS_URL);
            String binding = request.getParameter(BINDING);
            Integer index;
            try {
                index = Integer.valueOf(request.getParameter(INDEX));
            } catch (NumberFormatException nfe) {
                index = null;
            }
            acsURL = IDPSSOUtil.getACSurl(spEntityID, data.getRealm(), acsURL, binding, index, request,
                    returnedBinding);
            String acsBinding = returnedBinding.toString();
            IDPSSOUtil.sendResponse(request, response, out, acsBinding, spEntityID, data.getIdpEntityID(),
                    data.getIdpMetaAlias(), data.getRealm(), data.getRelayState(), acsURL, res, data.getSession());
        } catch (SAML2Exception sme) {
            SAML2Utils.debug.error(classMethod + "an error occured while sending error response", sme);
            throw new ServerFaultException(data.getIdpAdapter(), "UnableToGetAuthnReq");
        }

    }

    private boolean isSessionValid(SessionProvider sessionProvider) throws ServerFaultException,
            ClientFaultException, SessionException {

        final String classMethod = "UtilProxySAMLAuthenticatorLookup.validteSesison";

        // Let's verify if the session belongs to the proper realm
        boolean isValidSessionInRealm = data.getSession() != null &&
                IDPSSOUtil.isValidSessionInRealm(data.getRealm(), data.getSession());

        // There should be a session on the second pass. If this is not the case then provide an error message
        // If there is a session then it must belong to the proper realm
        if (!isValidSessionInRealm) {
            if (data.getAuthnRequest() != null && Boolean.TRUE.equals(data.getAuthnRequest().isPassive())) {
                // Send an appropriate response to the passive request
                data.setSpEntityID(data.getAuthnRequest().getIssuer().getValue());
                try {
                    IDPSSOUtil.sendResponseWithStatus(request, response, out, data.getIdpMetaAlias(),
                            data.getIdpEntityID(), data.getRealm(), data.getAuthnRequest(), data.getRelayState(),
                            data.getSpEntityID(), SAML2Constants.RESPONDER, SAML2Constants.NOPASSIVE);
                    return false;
                } catch (SAML2Exception sme) {
                    SAML2Utils.debug.error(classMethod, sme);
                    throw new ServerFaultException(data.getIdpAdapter(), METADATA_ERROR);
                }
            } else {
                // No attempt to authenticate now, since it is assumed that that has already been tried
                String ipAddress = request.getRemoteAddr();
                String authnReqString = "";
                try {
                    authnReqString = data.getAuthnRequest() == null ? "" : data.getAuthnRequest().toXMLString();
                } catch (SAML2Exception ex) {
                    SAML2Utils.debug.error(classMethod + "Could not obtain the AuthnReq to be logged");
                }

                if (data.getSession() == null) {
                    SAML2Utils.debug.error(classMethod + "The IdP has not been able to create a session");
                    logError(Level.INFO, LogUtil.SSO_NOT_FOUND, null, null, "null", data.getRealm(),
                            data.getIdpEntityID(), ipAddress, authnReqString);
                } else {
                    SAML2Utils.debug.error(classMethod + "The realm of the session does not correspond to that " +
                            "of the IdP");
                    logError(Level.INFO, LogUtil.INVALID_REALM_FOR_SESSION, data.getSession(), null,
                            sessionProvider.getProperty(data.getSession(), SAML2Constants.ORGANIZATION)[0],
                            data.getRealm(), data.getIdpEntityID(), ipAddress, authnReqString);
                }

                throw new ClientFaultException(data.getIdpAdapter(), SSO_OR_FEDERATION_ERROR);
            }
        }

        return true;
    }

    /**
     * Iterates through the RequestedAuthnContext from the Service Provider and
     * check if user has already authenticated with a sufficient authentication
     * level.
     * <p/>
     * If RequestAuthnContext is not found in the authenticated AuthnContext
     * then session upgrade will be done .
     *
     * @return true if the requester requires to re-authenticate
     */
    private static boolean isSessionUpgrade(IDPAuthnContextInfo idpAuthnContextInfo, Object session) {

        String classMethod = "IDPSSOFederate.isSessionUpgrade: ";

        if (session != null) {
            // Get the Authentication Context required
            String authnClassRef = idpAuthnContextInfo.getAuthnContext().
                    getAuthnContextClassRef();
            // Get the AuthN level associated with the Authentication Context
            int authnLevel = idpAuthnContextInfo.getAuthnLevel();

            SAML2Utils.debug.message(classMethod + "Requested AuthnContext: authnClassRef=" + authnClassRef +
                    " authnLevel=" + authnLevel);

            int sessionAuthnLevel = 0;

            try {
                final String strAuthLevel = SessionManager.getProvider().getProperty(session,
                        SAML2Constants.AUTH_LEVEL)[0];
                if (strAuthLevel.contains(":")) {
                    String[] realmAuthLevel = strAuthLevel.split(":");
                    sessionAuthnLevel = Integer.parseInt(realmAuthLevel[1]);
                } else {
                    sessionAuthnLevel = Integer.parseInt(strAuthLevel);
                }
                SAML2Utils.debug.message(classMethod + "Current session Authentication Level: " + sessionAuthnLevel);
            } catch (SessionException sex) {
                SAML2Utils.debug.error(classMethod + " Couldn't get the session Auth Level", sex);
            }

            return authnLevel > sessionAuthnLevel;
        } else {
            return true;
        }
    }

}
