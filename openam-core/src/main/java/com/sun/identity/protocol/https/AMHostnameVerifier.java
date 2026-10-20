/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2007 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * $Id: AMHostnameVerifier.java,v 1.2 2008/06/25 05:43:54 qcheng Exp $
 *
 * Portions Copyrighted 2026 OSSTech Corporation
 */

package com.sun.identity.protocol.https;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.StringTokenizer;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import com.iplanet.am.util.SystemProperties;
import com.iplanet.security.x509.CertUtils;
import com.sun.identity.shared.debug.Debug;


public class AMHostnameVerifier implements HostnameVerifier {

    public static boolean trustAllServerCerts = false;

    public static boolean checkSubjectAltName = false;

    public static boolean resolveIPAddress = false;

    public static HashSet sslTrustHosts = new HashSet();

    static private Debug debug = Debug.getInstance("amJSSE");
    
    static {
        String tmp = 
            SystemProperties.get("com.iplanet.am.jssproxy.trustAllServerCerts");
        trustAllServerCerts = (tmp != null && tmp.equalsIgnoreCase("true"));

        tmp = 
            SystemProperties.get("com.iplanet.am.jssproxy.checkSubjectAltName");
        checkSubjectAltName = (tmp != null && tmp.equalsIgnoreCase("true"));

        tmp = SystemProperties.get("com.iplanet.am.jssproxy.resolveIPAddress");
        resolveIPAddress = (tmp != null && tmp.equalsIgnoreCase("true"));

        tmp = SystemProperties.get(
            "com.iplanet.am.jssproxy.SSLTrustHostList", null);
        if (tmp != null) {
            getSSLTrustHosts(tmp);
        }

        if (debug.messageEnabled()) {
            debug.message("AMHostnameVerifier trustAllServerCerts = " +
                                   trustAllServerCerts);
            debug.message("AMHostnameVerifier checkSubjectAltName = " +
                                   checkSubjectAltName);
            debug.message("AMHostnameVerifier  resolveIPAddress = " +
                                   resolveIPAddress);
            debug.message("AMHostnameVerifier  SSLTrustHostList = " +
                                   sslTrustHosts.toString());
        }
    }

    public boolean verify(String hostname, SSLSession session) {
        if (trustAllServerCerts) {
            return true;
        }

        X509Certificate peercert = null;
        String cn = null;

        try {
            X509Certificate[] peercerts = 
                   (X509Certificate[]) session.getPeerCertificates();
            peercert =  peercerts[0];
            cn = CertUtils.getAttributeValue(peercerts[0].getSubjectX500Principal(), "CN");
        } catch (Exception ex) {
            debug.error("AMHostnameVerifier:"+ex.toString());
        }

        if (cn == null) 
            return false;

        if (!sslTrustHosts.isEmpty()) {
            if (sslTrustHosts.contains(cn.toLowerCase())) {
                return true;
            }
        }

        if (resolveIPAddress) {
            try {
                if (InetAddress.getByName(cn).getHostAddress().equals(
                        InetAddress.getByName(hostname).getHostAddress())) {
                    return true;
                }
            }
            catch (UnknownHostException ex) {
                if (debug.messageEnabled()) {
                    debug.message("AMHostnameVerifier:", ex);
                }
            }
        }
        
        if (checkSubjectAltName) {
            try {
                Collection<List<?>> subjectAltNames = peercert.getSubjectAlternativeNames();
                if (subjectAltNames == null || subjectAltNames.isEmpty()) {
                    debug.message("AMHostnameVerifier: subjectAltNames is null or empty");
                    return false;
                }
                for (List<?> generalName : subjectAltNames) {
                    if (compareHosts(generalName, hostname)) {
                        return true;
                    }
                }
            } catch (Exception ex) {
                debug.message("AMHostnameVerifier: Failed to verify with Subject Alternative Name", ex);
            }
        }
        
        return false;
    }

    private boolean compareHosts(List<?> generalName, String hostname) {
        if (generalName == null) {
            debug.message("AMHostnameVerifier.compareHosts: generalName is null");
            return false;
        }

        // generalName contains at least 2 elements.
        // The first element is an Integer representing the name type.
        // The second element is a String or a byte array and represents the name value.
        // The following if statement checks whether the name type is DNSName(2).
        if ((Integer) generalName.get(0) != 2) {
            return false;
        }

        // get the DNSName value
        Object name = generalName.get(1);
        if (!(name instanceof String)) {
            debug.message("AMHostnameVerifier.compareHosts: DNSName value is not String, type: {}",
                    name.getClass().getName());
            return false;
        }

        try {
            return InetAddress.getByName((String) name).equals(
                    InetAddress.getByName(hostname));
        } catch (UnknownHostException e) {
            debug.message("AMHostnameVerifier.compareHosts: {}", e.toString());
        }

        return false;
    }

    static private void getSSLTrustHosts(String hostlist) {
        if (debug.messageEnabled()) {
            debug.message("AMHostnameVerifier  SSLTrustHostList = " +
                                   hostlist);
        }
        StringTokenizer st = new StringTokenizer(hostlist, ",");
        sslTrustHosts.clear();
        while (st.hasMoreTokens()) {
            sslTrustHosts.add(((String)st.nextToken()).trim().toLowerCase());
        }
    }
}
        
