<%--
   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
  
   Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
  
   The contents of this file are subject to the terms
   of the Common Development and Distribution License
   (the License). You may not use this file except in
   compliance with the License.

   You can obtain a copy of the License at
   https://opensso.dev.java.net/public/CDDLv1.0.html or
   opensso/legal/CDDLv1.0.txt
   See the License for the specific language governing
   permission and limitations under the License.

   When distributing Covered Code, include this CDDL
   Header Notice in each file and include the License file
   at opensso/legal/CDDLv1.0.txt.
   If applicable, add the following below the CDDL Header,
   with the fields enclosed by brackets [] replaced by
   your own identifying information:
   "Portions Copyrighted [year] [name of copyright owner]"

   $Id: multi.jsp,v 1.1 2009/07/02 22:00:17 exu Exp $

   Portions Copyrighted 2013 ForgeRock AS
   Portions Copyrighted 2026 OSSTech Corporation
--%>

<%@page
    import="com.sun.identity.wsfederation.common.WSFederationConstants"
    import="com.sun.identity.plugin.session.SessionManager"
    import="com.sun.identity.wsfederation.common.WSFederationUtils"
    import="com.sun.identity.saml2.common.SAML2Constants"
    import="org.owasp.esapi.ESAPI"
%><%
    // handle multi-federation protocol case
    Object uSession = null;
    try {
        uSession = SessionManager.getProvider().getSession(request);
    } catch (Exception e) {
    }

    String realm = request.getParameter(
        WSFederationConstants.REALM_PARAM);
    if (!ESAPI.validator().isValidInput("HTTP Parameter Value: " + realm,
        realm, "HTTPParameterValue", 2000, true)){
            realm = null;
    }
    String entityID = request.getParameter(
        WSFederationConstants.ENTITYID_PARAM);
    // HTTPParameterValue has no ":" in its character class, so it rejects entity IDs written as URIs. Only to
    // look up the wreplyList, the entity ID is kept when it is short and holds no control characters.
    String wreplyEntityID = entityID;
    if (wreplyEntityID != null) {
        if (wreplyEntityID.length() > 2000) {
            wreplyEntityID = null;
        } else {
            for (int i = 0; i < wreplyEntityID.length(); i++) {
                if (Character.isISOControl(wreplyEntityID.charAt(i))) {
                    wreplyEntityID = null;
                    break;
                }
            }
        }
    }
    if (!ESAPI.validator().isValidInput("HTTP Parameter Value: " + entityID,
        entityID, "HTTPParameterValue", 2000, true)){
            entityID = null;
    }

    // The wreply parameter ends up in a redirect, on the unauthenticated path as well. Accept only URLs pointing
    // at this server, or matching the wreplyList of the entity - which may be hosted as the IdP or the RP.
    String wreply = request.getParameter(WSFederationConstants.LOGOUT_WREPLY);
    if (!WSFederationUtils.isWReplyURLAllowed(request, realm, wreplyEntityID, wreply,
            SAML2Constants.IDP_ROLE, SAML2Constants.SP_ROLE)) {
        if ((wreply != null) && (wreply.length() != 0)) {
            WSFederationUtils.debug.warning("multi.jsp: the wreply URL is not allowed and is ignored");
        }
        wreply = null;
    }

    if ((uSession == null) || !SessionManager.getProvider().isValid(uSession)) {
        if ((wreply != null) && (wreply.length() != 0)) {
            response.sendRedirect(wreply);
        }
    } else {
        request.setAttribute(WSFederationConstants.LOGOUT_WREPLY, wreply);
        request.setAttribute(WSFederationConstants.REALM_PARAM, realm);
        request.setAttribute(WSFederationConstants.ENTITYID_PARAM, entityID);

        WSFederationUtils.processMultiProtocolLogout(request, response, uSession);
    }
%>
