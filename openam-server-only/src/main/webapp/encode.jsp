<%--
   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
  
   Copyright (c) 2008 Sun Microsystems, Inc. All Rights Reserved.
  
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
  
   $Id: encode.jsp,v 1.13 2008/12/05 17:53:39 veiming Exp $
--%>

<%--
   Portions copyright 2010-2014 ForgeRock AS.
   Portions copyright 2019 Open Source Solution Technology Corporation
--%>

<%@page contentType="text/html; charset=UTF-8" %> 
<html>
<head>
    <title>OpenAM</title>
    <link rel="stylesheet" type="text/css" href="com_sun_web_ui/css/css_ns6up.css" />
    <link rel="shortcut icon" href="com_sun_web_ui/images/favicon/favicon.ico" type="image/x-icon" />
</head>

<%@page import="com.iplanet.sso.SSOException" %>
<%@page import="com.iplanet.sso.SSOToken" %>
<%@page import="com.sun.identity.security.EncodeAction" %>
<%@page import="com.sun.identity.shared.locale.Locale" %>
<%@page import="java.security.AccessController" %>
<%@page import="java.util.ResourceBundle" %>

<body class="DefBdy">
    <div class="SkpMedGry1"><a href="#SkipAnchor3860"><img src="com_sun_web_ui/images/other/dot.gif" alt="Jump to End of Masthead" border="0" height="1" width="1" /></a></div><div class="MstDiv">
    <table class="MstTblBot" title="" border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
        <td class="MstTdTtl">
        <div class="MstDivTtl"><img name="AMConfig.configurator.ProdName" src="com_sun_web_ui/images/PrimaryProductName.png" alt="OpenAM" border="0" /></div>
        </td>
        </tr>
    </table>
    </div>
    <table class="SkpMedGry1" border="0" cellpadding="5" cellspacing="0" width="100%"><tr><td><img src="com_sun_web_ui/images/other/dot.gif" alt="Jump to End of Masthead" border="0" height="1" width="1" /></a></td></tr></table>
    <table border="0" cellpadding="10" cellspacing="0" width="100%"><tr><td></td></tr></table>

<%@ include file="/WEB-INF/jsp/admincheck.jsp" %>
<%

    SSOToken ssoToken = requireAdminSSOToken(request, response, out, "encode.jsp");
    if (ssoToken == null) {
%>
</body></html>
<%
        return;
    }
%>
    <table border="0" cellpadding="10" cellspacing="0" width="100%"><tr><td>
<%
    String ssoPropLocale;
    try {
        ssoPropLocale = ssoToken.getProperty("Locale");
    } catch (SSOException e) {
        response.sendRedirect("UI/Login?goto=../encode.jsp");
        return;
    }

    request.setCharacterEncoding("UTF-8");

    ResourceBundle rb =
        ((ssoPropLocale != null) && (ssoPropLocale.length() > 0)) ?
        ResourceBundle.getBundle("encode", Locale.getLocale(ssoPropLocale)) :
        ResourceBundle.getBundle("encode");

    String strPwd = request.getParameter("password");

    if ((strPwd != null) && (strPwd.trim().length() > 0))  {
        out.println(rb.getString("result-encoded-pwd") + " ");
        out.println(AccessController.doPrivileged(new EncodeAction(strPwd.trim())));
        out.println("<br /><br /><a href=\"encode.jsp\">" + rb.getString("encode-another-pwd") + "</a>");
    } else {
        out.println("<form name=\"frm\" action=\"encode.jsp\" method=\"post\">");
        out.println(rb.getString("prompt-pwd"));
        out.println("<input type=\"text\" name=\"password\" autocomplete=\"off\" />");
        out.println("<input type=\"submit\" value=\"" + rb.getString("btn-encode") + "\" />");
        out.println("</form>");
    }

%>
    </td></tr></table>

</body></html>
