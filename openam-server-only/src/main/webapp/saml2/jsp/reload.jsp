<%--
   The contents of this file are subject to the terms of the Common Development and
   Distribution License (the License). You may not use this file except in compliance with the
   License.

   You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
   specific language governing permission and limitations under the License.

   When distributing Covered Software, include this CDDL Header Notice in each file and include
   the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
   Header, with the fields enclosed by brackets [] replaced by your own identifying
   information: "Portions copyright [year] [name of copyright owner]".

   Copyright 2026 OSSTech Corporation

--%>

<%@ page import="jp.co.osstech.openam.saml2.metadata.MetadataReloadTask" %>
<%@ page import="jp.co.osstech.openam.saml2.metadata.MetadataReloadTaskFactory" %>
<%@ page import="java.security.AccessController" %>
<%@ page import="com.iplanet.am.util.SystemProperties" %>
<%@ page import="com.iplanet.sso.SSOException" %>
<%@ page import="com.iplanet.sso.SSOToken" %>
<%@ page import="com.iplanet.sso.SSOTokenManager" %>
<%@ page import="com.sun.identity.idm.AMIdentity" %>
<%@ page import="com.sun.identity.idm.IdRepoException" %>
<%@ page import="com.sun.identity.idm.IdType" %>
<%@ page import="com.sun.identity.security.AdminTokenAction" %>
<%@ page import="java.util.Optional" %>

<%
        String adminUUID = null;
        String adminUser = SystemProperties.get("com.sun.identity.authentication.super.user");
        if (adminUser != null) {
            SSOToken adminToken = (SSOToken) AccessController.doPrivileged(AdminTokenAction.getInstance());
            AMIdentity adminUserIdentity = new AMIdentity(adminToken, adminUser, IdType.USER, "/", null);
            adminUUID = adminUserIdentity.getUniversalId();
        }

        try {
            SSOTokenManager manager = SSOTokenManager.getInstance();
            SSOToken token = manager.createSSOToken(request);

            if (!manager.isValidToken(token)) {
                String redirectURL = request.getScheme() + "://"
                        + request.getServerName() + ":"
                        + request.getServerPort()
                        + request.getContextPath();
                response.sendRedirect(redirectURL);
                return;
            }

            AMIdentity user = new AMIdentity(token);
            if (!user.getUniversalId().equalsIgnoreCase(adminUUID)) {
                out.println("This action is only allowed for admin user.");
                return;
            }

        } catch (SSOException|IdRepoException e) {
            String redirectURL = request.getScheme() + "://"
                    + request.getServerName() + ":"
                    + request.getServerPort()
                    + request.getContextPath();
            response.sendRedirect(redirectURL);
            return;
        }
        String realm = request.getParameter("realm");
        if (realm == null) {
            realm = "/";
        }

        MetadataReloadTaskFactory factory = new MetadataReloadTaskFactory();
        Optional<MetadataReloadTask> optTask = factory.getReloadTask(realm);
        if (!optTask.isPresent()) {
            out.println("SAML2 metadata reload is not configured in this realm.");
            return;
        }
        MetadataReloadTask task = optTask.get();
        try {
            task.execute();
            out.println("Complete");
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
%>
