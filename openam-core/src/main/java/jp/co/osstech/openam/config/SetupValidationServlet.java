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

package jp.co.osstech.openam.config;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.opendj.ldap.LDAPConnectionFactory.AUTHN_BIND_REQUEST;
import static org.forgerock.opendj.ldap.LDAPConnectionFactory.CONNECT_TIMEOUT;
import static org.forgerock.opendj.ldap.LDAPConnectionFactory.SSL_CONTEXT;
import static org.forgerock.util.time.Duration.duration;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.services.util.Crypt;
import com.sun.identity.common.configuration.ConfigurationException;
import com.sun.identity.setup.AMSetupUtils;
import com.sun.identity.setup.BootstrapData;
import com.sun.identity.setup.ConfiguratorException;
import com.sun.identity.setup.SetupConstants;
import com.sun.identity.shared.Constants;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.ldap.LDAPRequests;
import org.forgerock.openam.ldap.LDAPUtils;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.ConnectionFactory;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LdapException;
import org.forgerock.opendj.ldap.SSLContextBuilder;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.util.Options;

/**
 * This class validate parameters sent from the client for initial setup.
 */

public class SetupValidationServlet extends HttpServlet {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, String>> MAP_TYPE = new TypeReference<Map<String, String>>() {
    };

    protected void writeError(HttpServletResponse response, String i18nkey) throws IOException {
        response.setContentType("application/json; charset=UTF-8");
        JsonValue json = json(object(field("error", object(field("code", i18nkey)))));
        PrintWriter out = response.getWriter();
        out.println(json.toString());
    }

    protected void writeValid(HttpServletResponse response) throws IOException {
        response.setContentType("application/json; charset=UTF-8");
        JsonValue json = json(object(field("message", "ok")));
        PrintWriter out = response.getWriter();
        out.println(json.toString());
    }

    protected ConnectionFactory getConnectionFactory(String host, int port, String bindDN, char[] bindPwd, int timeout,
            boolean isSSl)
            throws GeneralSecurityException, LdapException {
        Options ldapOptions = Options.defaultOptions().set(CONNECT_TIMEOUT, duration((long) timeout, TimeUnit.SECONDS))
                .set(AUTHN_BIND_REQUEST, LDAPRequests.newSimpleBindRequest(bindDN, bindPwd));

        if (isSSl) {
            String defaultProtocolVersion = SystemProperties.get(Constants.LDAP_SERVER_TLS_VERSION, "TLSv1.2");
            ldapOptions = ldapOptions.set(SSL_CONTEXT,
                    new SSLContextBuilder().setProtocol(defaultProtocolVersion).getSSLContext());
        }

        return new LDAPConnectionFactory(host, port, ldapOptions);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        Map<String, String> requestParams = MAPPER.readValue(request.getReader(), MAP_TYPE);
        String type = requestParams.get("type");
        switch (type) {
            case "configDirectory":
                validateConfigDirectory(requestParams, response);
                break;
            case "configStoreHost":
                validateConfigStoreHost(requestParams, response);
                break;
            case "ldapConnection":
                validateLdapConnection(requestParams, response);
                break;
            case "localPort":
                validateLocalPort(requestParams, response);
                break;
            case "remoteServer":
                validateRemoteServer(requestParams, response);
                break;
            case "rootSuffix":
                validateRootSuffix(requestParams, response);
                break;
        }
    }

    public void validateConfigDirectory(Map<String, String> params, HttpServletResponse response)
            throws IOException, ServletException {
        String configDir = params.get("dir");

        if (!hasWritePermission(configDir)) {
            writeError(response, "error.noWritePermissionToBasedir");
        } else if (alreadyHasContent(configDir)) {
            writeError(response, "error.basedirIsNotEmpty");
        } else {
            writeValid(response);
        }
    }

    public void validateConfigStoreHost(Map<String, String> params, HttpServletResponse response)
            throws IOException, ServletException {
        String host = params.get("host");
        try {
            InetAddress.getByName(host);
            writeValid(response);
        } catch (UnknownHostException e) {
            writeError(response, "error.unknownHost");
        }
    }

    public void validateLdapConnection(Map<String, String> params, HttpServletResponse response)
            throws IOException, ServletException {
        String type = params.get("dstype");
        boolean ssl = false;
        String sslStr = params.get("ssl");
        if ("SSL".equals(sslStr)) {
            ssl = true;
        }
        String host = params.get("host");
        int port = 389;
        if (!"AD".equals(type)) {
            String portStr = params.get("port");
            try {
                port = Integer.parseInt(portStr);
            } catch (NumberFormatException e) {
                writeError(response, "error.invalidPortNumber");
                return;
            }
        }
        String bindDN = params.get("bindDN");
        String rootSuffix = params.get("rootSuffix");
        String password = params.get("password");
        int timeout = 5;

        if ("AD".equals(type)) {
            String domainName = params.get("domainName");
            try {
                String[] hostAndPort = getLdapHostAndPort(domainName);
                host = hostAndPort[0];
                port = Integer.parseInt(hostAndPort[1]);
                rootSuffix = dnsDomainToDN(domainName);
            } catch (NamingException | IOException e) {
                writeError(response, "error.cannotConnectAD");
                return;
            }
        }

        try (ConnectionFactory factory = getConnectionFactory(host, port, bindDN, password.toCharArray(), timeout,
                ssl)) {
            try (Connection conn = factory.getConnection()) {
                String filter = "(objectclass=*)";
                String[] attrs = { "" };
                conn.search(LDAPRequests.newSearchRequest(rootSuffix, SearchScope.BASE_OBJECT, filter, attrs));
                if ("AD".equals(type)) {
                    Map<String, String> responseParams = new HashMap<String, String>();
                    responseParams.put("message", "ok");
                    responseParams.put("host", host);
                    responseParams.put("port", String.valueOf(port));
                    responseParams.put("rootSuffix", rootSuffix);
                    JsonValue json = new JsonValue(responseParams);
                    response.setContentType("application/json; charset=UTF-8");
                    PrintWriter out = response.getWriter();
                    out.println(json.toString());
                } else {
                    writeValid(response);
                }
            }
        } catch (LdapException | GeneralSecurityException e) {
            writeError(response, "error.cannotConnectDatastore");
        }
    }

    public void validateLocalPort(Map<String, String> params, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            int port = Integer.parseInt(params.get("port"));
            String host = "localhost";

            if (AMSetupUtils.isPortInUse(host, port)) {
                writeValid(response);
            } else {
                writeError(response, "error.portUsed");
            }
        } catch (NumberFormatException e) {
            writeError(response, "error.invalidPortNumber");
        }
    }

    public void validateRemoteServer(Map<String, String> params, HttpServletResponse response)
            throws IOException, ServletException {
        String host = params.get("host");
        String user = "amadmin";
        String password = params.get("password");
        try {
            Map data = AMSetupUtils.getRemoteServerInfo(host, user, password);
            String encryptedPassword = (String) data.get(BootstrapData.DS_PWD);
            String rawPassword = Crypt.decode(encryptedPassword, Crypt.getHardcodedKeyEncryptor());
            data.put(SetupConstants.CONFIG_VAR_DS_MGR_PWD, rawPassword);
            JsonValue json = json(data);
            response.getWriter().println(json.toString());
        } catch (ConfigurationException | ConfiguratorException e) {
            String code = e.getErrorCode();
            writeError(response, "error." + code);
        }
    }

    public void validateRootSuffix(Map<String, String> params, HttpServletResponse response)
            throws IOException, ServletException {
        String rootsuffix = params.get("rootSuffix");
        if (!LDAPUtils.isDN(rootsuffix)) {
            writeError(response, "error.invalidDN");
        } else {
            writeValid(response);
        }
    }

    private static boolean hasWritePermission(String dirName) {
        File f = new File(dirName);
        while ((f != null) && !f.exists()) {
            f = f.getParentFile();
        }
        return (f == null) ? false : f.isDirectory() && f.canWrite();
    }

    private static boolean alreadyHasContent(String dirName) {
        File f = new File(dirName);

        if (f.exists() && f.isDirectory()) {
            return (f.list().length > 0);
        }

        return false;
    }

    private String[] getLdapHostAndPort(String domainName) throws NamingException, IOException {
        if (!domainName.endsWith(".")) {
            domainName += '.';
        }
        DirContext ictx = null;
        // Check if domain name is a valid one.
        // The resource record type A is defined in RFC 1035.
        try {
            Hashtable<String, String> env = new Hashtable<String, String>();
            env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            ictx = new InitialDirContext(env);
            Attributes attributes = ictx.getAttributes(domainName, new String[] { "A" });
            Attribute attrib = attributes.get("A");
            if (attrib == null) {
                throw new NamingException();
            }
        } catch (NamingException e) {
            // Failed to resolve domainName to A record.
            // throw exception.
            throw e;
        }

        // then look for the LDAP server
        String serverHostName = null;
        String serverPortStr = null;
        final String ldapServer = "_ldap._tcp." + domainName;
        try {
            // Attempting to resolve ldapServer to SRV record.
            // This is a mechanism defined in MSDN, querying
            // SRV records for _ldap._tcp.DOMAINNAME.
            // and get host and port from domain.
            Attributes attributes = ictx.getAttributes(ldapServer, new String[] { "SRV" });
            Attribute attr = attributes.get("SRV");
            if (attr == null) {
                throw new NamingException();
            }
            String[] srv = attr.get().toString().split(" ");
            String hostNam = srv[3];
            serverHostName = hostNam.substring(0, hostNam.length() - 1);
            serverPortStr = srv[2];
        } catch (NamingException e) {
            // Failed to resolve ldapServer to SRV record.
            // throw exception.
            throw e;
        }

        // try to connect to LDAP port to make sure this machine
        // has LDAP service
        int serverPort = Integer.parseInt(serverPortStr);
        try {
            new Socket(serverHostName, serverPort).close();
        } catch (IOException e) {
            throw e;
        }

        String[] hostAndPort = new String[2];
        hostAndPort[0] = serverHostName;
        hostAndPort[1] = serverPortStr;

        return hostAndPort;
    }

    private String dnsDomainToDN(String domainName) {
        StringBuilder buf = new StringBuilder();
        for (String token : domainName.split("\\.")) {
            if (token.length() == 0)
                continue;
            if (buf.length() > 0)
                buf.append(",");
            buf.append("DC=").append(token);
        }
        return buf.toString();
    }
}
