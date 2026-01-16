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
 * Copyright 2019-2026 OSSTech Corporation
 */
package jp.co.osstech.openam.core.rest.devices.services.webauthn;

import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import com.iplanet.sso.SSOException;
import com.sun.identity.common.ShutdownManager;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import org.forgerock.openam.core.rest.devices.DeviceSerialisation;
import org.forgerock.openam.core.rest.devices.services.DeviceService;
import org.forgerock.openam.ldap.LDAPRequests;
import org.forgerock.openam.ldap.LDAPURL;
import org.forgerock.openam.ldap.LDAPUtilException;
import org.forgerock.openam.ldap.LDAPUtils;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.IOUtils;
import org.forgerock.opendj.ldap.Attribute;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.ConnectionFactory;
import org.forgerock.opendj.ldap.Connections;
import org.forgerock.opendj.ldap.DN;
import org.forgerock.opendj.ldap.Entry;
import org.forgerock.opendj.ldap.Filter;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LdapException;
import org.forgerock.opendj.ldap.LinkedHashMapEntry;
import org.forgerock.opendj.ldap.ModificationType;
import org.forgerock.opendj.ldap.SSLContextBuilder;
import org.forgerock.opendj.ldap.SearchResultReferenceIOException;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.TrustManagers;
import org.forgerock.opendj.ldap.requests.ModifyRequest;
import org.forgerock.opendj.ldap.requests.SearchRequest;
import org.forgerock.opendj.ldap.responses.SearchResultEntry;
import org.forgerock.opendj.ldif.ConnectionEntryReader;
import org.forgerock.util.Options;
import org.forgerock.util.thread.listener.ShutdownListener;
import org.forgerock.util.time.Duration;

/**
 * Implementation of the WebAuthn Authenticator Service.
 * Provides all necessary configuration information at a realm-wide level to
 * WebAuthn authentication modules underneath it.
 */
public class AuthenticatorWebAuthnService implements DeviceService {

    /** Name of this service for reference purposes. */
    public static final String SERVICE_NAME = "AuthenticatorWebAuthn";
    /** Version of this service. */
    public static final String SERVICE_VERSION = "1.0";

    private static final String DEBUG_LOCATION = "AuthenticatorWebAuthnService";

    private static final String WEBAUTHN_CLASS_NAMES =
            "openam-auth-webauthn-objectclass-names";
    private static final String WEBAUTHN_CREDENTIAL_ATTRIBUTE_NAME =
            "openam-auth-webauthn-credentialid-attribute-name";
    private static final String WEBAUTHN_KEY_ATTRIBUTE_NAME =
            "openam-auth-webauthn-key-attribute-name";
    private static final String WEBAUTHN_CREDENTIALNAME_ATTRIBUTE_NAME =
            "openam-auth-webauthn-credentialname-attribute-name";
    private static final String WEBAUTHN_COUNTER_ATTRIBUTE_NAME =
            "openam-auth-webauthn-counter-attribute-name";
    private static final String WEBAUTHN_USER_HANDLE_ID_ATTRIBUTE_NAME =
            "openam-auth-webauthn-user-handle-id-attribute-name";

    private static final String WEBAUTHN_PRIMARY_LDAP_SERVER =
            "openam-auth-webauthn-ldap-server";
    private static final String WEBAUTHN_SECONDARY_LDAP_SERVER =
            "openam-auth-wbauthn-ldap-server2";
    private static final String WEBAUTHN_LDAP_BASE_DN =
            "openam-auth-webauthn-ldap-base-dn";
    private static final String WEBAUTHN_LDAP_BIND_DN =
            "openam-auth-webauthn-ldap-bind-dn";
    private static final String WEBAUTHN_LDAP_BIND_PASSWORD =
            "openam-auth-webauthn-ldap-bind-passwd";
    private static final String WEBAUTHN_LDAP_CONNECTION_MODE =
            "openam-auth-webauthn-ldap-connection-mode";
    private static final String WEBAUTHN_LDAP_TLS_VERSION =
            "openam-auth-webauthn-ldap-secure-protocol-version";
    private static final String WEBAUTHN_LDAP_TLS_TRUST_ALL =
            "openam-auth-webauthn-ldap-ssl-trust-all";
    private static final String WEBAUTHN_LDAP_HEARTBEAT_INTERVAL =
            "openam-auth-webauthn-ldap-heartbeat-interval";
    private static final String WEBAUTHN_LDAP_HEARTBEAT_TIMEUNIT =
            "openam-auth-webauthn-ldap-heartbeat-timeunit";
    private static final String WEBAUTHN_LDAP_OPERATION_TIMEOUT =
            "openam-auth-webauthn-ldap-operation-timeout";
    private static final String WEBAUTHN_LDAP_CON_POOL_MAX_SIZE =
            "openam-auth-webauthn-ldap-connection-pool-max-size";

    private static final Set<String> DEFAULT_WEBAUTHN_CLASS_NAMES =
            CollectionUtils.asSet("top", "fido2Credential");
    private static final String DEFAULT_WEBAUTHN_CREDENTIAL_ATTRIBUTE_NAME =
            "fido2CredentialID";
    private static final String DEFAULT_WEBAUTHN_KEY_ATTRIBUTE_NAME =
            "fido2PublicKey";
    private static final String DEFAULT_WEBAUTHN_CREDENTIALNAME_ATTRIBUTE_NAME =
            "fido2CredentialName";
    private static final String DEFAULT_WEBAUTHN_COUNTER_ATTRIBUTE_NAME =
            "fido2SignCount";
    private static final String DEFAULT_WEBAUTHN_USER_HANDLE_ID_ATTRIBUTE_NAME =
            "fido2UserID";
    private final static int DEFAULT_CON_POOL_MAX_SIZE = 10;

    final private Debug debug;
    final private String realm;
    private Map<String, Set<?>> options;
    private Set<String> classNames = null;
    private String credentialAttrName = null;
    private String keyAttrName = null;
    private String credentialNameAttrName = null;
    private String counterAttrName = null;
    private String useridAttrName = null;
    private String baseDN = null;
    private ConnectionFactory cPool = null;
    private boolean isValidService = false;

    /**
     * Basic constructor for the AuthenticatorWebAuthnService.
     *
     * @param configManager For communicating with the config datastore with listeners.
     * @param realm The realm in which this service instance exists.
     * @throws SMSException If we cannot talk to the config service.
     * @throws SSOException If we do not have correct permissions.
     */
    public AuthenticatorWebAuthnService(ServiceConfigManager configManager, String realm)
            throws SMSException, SSOException {
        debug = Debug.getInstance(DEBUG_LOCATION);
        this.realm = realm;

        try {
            ServiceConfig scm = configManager.getOrganizationConfig(realm, null);
            options = scm.getAttributesWithoutDefaults();
            if (options.isEmpty()) {
                debug.warning("AuthenticatorWebAuthnService in {} realm does not exist.", realm);
                return;
            }

            baseDN = CollectionHelper.getMapAttr(options, WEBAUTHN_LDAP_BASE_DN);
            if (baseDN == null) {
                debug.error("BaseDN for search was null");
            }
            classNames = (Set<String>) options.get(WEBAUTHN_CLASS_NAMES);
            if (classNames == null || classNames.size() == 0) {
                classNames = DEFAULT_WEBAUTHN_CLASS_NAMES;
            }
            credentialAttrName = CollectionHelper.getMapAttr(options, WEBAUTHN_CREDENTIAL_ATTRIBUTE_NAME,
                    DEFAULT_WEBAUTHN_CREDENTIAL_ATTRIBUTE_NAME);
            keyAttrName = CollectionHelper.getMapAttr(options, WEBAUTHN_KEY_ATTRIBUTE_NAME,
                    DEFAULT_WEBAUTHN_KEY_ATTRIBUTE_NAME);
            credentialNameAttrName = CollectionHelper.getMapAttr(options, WEBAUTHN_CREDENTIALNAME_ATTRIBUTE_NAME,
                    DEFAULT_WEBAUTHN_CREDENTIALNAME_ATTRIBUTE_NAME);
            counterAttrName = CollectionHelper.getMapAttr(options, WEBAUTHN_COUNTER_ATTRIBUTE_NAME,
                    DEFAULT_WEBAUTHN_COUNTER_ATTRIBUTE_NAME);
            useridAttrName = CollectionHelper.getMapAttr(options, WEBAUTHN_USER_HANDLE_ID_ATTRIBUTE_NAME,
                    DEFAULT_WEBAUTHN_USER_HANDLE_ID_ATTRIBUTE_NAME);

            isValidService = true;

        } catch (SMSException | SSOException e) {
            debug.error("Error connecting to SMS to retrieve config for AuthenticatorWebAuthnService.", e);
            throw e;
        }
    }

    /**
     * Initialize the LDAP connection pool.
     * 
     * @throws LDAPUtilException
     */
    private void initializeConnection() throws LDAPUtilException {
        debug.message("LDAP initialize()");

        Set<String> primaryServers =
                CollectionHelper.getServerMapAttrs(options, WEBAUTHN_PRIMARY_LDAP_SERVER);
        Set<String> secondaryServers =
                CollectionHelper.getServerMapAttrs(options, WEBAUTHN_SECONDARY_LDAP_SERVER);

        String bindDN =
                CollectionHelper.getMapAttr(options, WEBAUTHN_LDAP_BIND_DN, "");
        char[] bindPassword =
                CollectionHelper.getMapAttr(options, WEBAUTHN_LDAP_BIND_PASSWORD, "").toCharArray();
        String connectionMode =
                CollectionHelper.getMapAttr(options, WEBAUTHN_LDAP_CONNECTION_MODE, "LDAP");
        boolean useStartTLS = connectionMode.equalsIgnoreCase("StartTLS");
        boolean isSecure = connectionMode.equalsIgnoreCase("LDAPS") || useStartTLS;
        String protocolVersion =
                CollectionHelper.getMapAttr(options, WEBAUTHN_LDAP_TLS_VERSION, "TLSv1");

        boolean sslTrustAll = Boolean.valueOf(
                    CollectionHelper.getMapAttr(options, WEBAUTHN_LDAP_TLS_TRUST_ALL, "false")).booleanValue();
        int heartBeatInterval =
                CollectionHelper.getIntMapAttr(options, WEBAUTHN_LDAP_HEARTBEAT_INTERVAL, 10, debug);
        String heartBeatTimeUnit =
                CollectionHelper.getMapAttr(options, WEBAUTHN_LDAP_HEARTBEAT_TIMEUNIT, "SECONDS");
        int operationTimeout =
                CollectionHelper.getIntMapAttr(options, WEBAUTHN_LDAP_OPERATION_TIMEOUT , 0 , debug);
        int maxPoolSize =
                CollectionHelper.getIntMapAttr(options, WEBAUTHN_LDAP_CON_POOL_MAX_SIZE,
                        DEFAULT_CON_POOL_MAX_SIZE, debug);

        try {
            Options options = Options.defaultOptions()
                    .set(LDAPConnectionFactory.REQUEST_TIMEOUT,
                            new Duration((long) operationTimeout, TimeUnit.SECONDS));

            Set<LDAPURL> primaryUrls = LDAPUtils.convertToLDAPURLs(primaryServers);
            Set<LDAPURL> secondaryUrls = LDAPUtils.convertToLDAPURLs(secondaryServers);

            if (isSecure) {
                SSLContextBuilder builder = new SSLContextBuilder();

                if (sslTrustAll) {
                    builder.setTrustManager(TrustManagers.trustAll());
                }

                SSLContext sslContext = builder.setProtocol(protocolVersion).getSSLContext();
                options.set(LDAPConnectionFactory.SSL_CONTEXT, sslContext);
                if (useStartTLS) {
                    options.set(LDAPConnectionFactory.SSL_USE_STARTTLS, true);
                }
            }

            ConnectionFactory primaryCf = LDAPUtils.newFailoverConnectionPool(primaryUrls, bindDN,
                    bindPassword, maxPoolSize, heartBeatInterval, heartBeatTimeUnit, options);
            if (secondaryServers.isEmpty()) {
                cPool = primaryCf;
            } else {
                ConnectionFactory secondaryCf = LDAPUtils.newFailoverConnectionPool(secondaryUrls, bindDN,
                        bindPassword, maxPoolSize, heartBeatInterval, heartBeatTimeUnit, options);
                cPool = Connections.newFailoverLoadBalancer(CollectionUtils.asList(primaryCf, secondaryCf), options);
            }

            ShutdownManager shutdownMan = com.sun.identity.common.ShutdownManager.getInstance();
            shutdownMan.addShutdownListener(new ShutdownListener() {
                public void shutdown() {
                    cPool.close();
                }
            });

        } catch (GeneralSecurityException e) {
            debug.error("Unable to create connection pool", e);
            throw new LDAPUtilException(e);
        }
    }

    /**
     * Get a connection from the connection pool.
     * 
     * @return The LDAP connection.
     * @throws LdapException If the connection request failed for some reason.
     * @throws LDAPUtilException
     */
    private Connection getConnection() throws LdapException, LDAPUtilException {
        synchronized(this) {
            if (cPool == null) {
                initializeConnection();
            }
        }
        return cPool.getConnection();
    }

    /**
     * Returns whether AuthenticatorWebAuthnService is valid.
     *
     * @return true if AuthenticatorWebAuthnService is valid.
     */
    public boolean isValid() {
        return isValidService;
    }

    /**
     * Create an LDAP entry for the authenticator.
     * 
     * @param authenticator The target authenticator.
     * @return Returns true if the entry is successfully saved.
     */
    public boolean createAuthenticator(WebAuthnAuthenticator authenticator) {
        boolean result = false;
        if (!isValid()) {
            debug.error("AuthenticatorWebAuthnService in {} realm is invalid.", realm);
            return result;
        }
        String dn = DN.valueOf(baseDN)
                .child(credentialAttrName, authenticator.getCredentialID()).toString();
        Entry entry = new LinkedHashMapEntry(dn);
        Set<String> objectClasses = classNames;
        entry.addAttribute("objectClass", objectClasses.toArray());
        entry.addAttribute(credentialAttrName, authenticator.getCredentialID());
        entry.addAttribute(keyAttrName, authenticator.getPublicKey());
        entry.addAttribute(counterAttrName, authenticator.getSignCount());
        entry.addAttribute(credentialNameAttrName, authenticator.getCredentialName());
        entry.addAttribute(useridAttrName, authenticator.getUserID());

        Connection conn = null;
        try {
            conn = getConnection();
            conn.add(LDAPRequests.newAddRequest(entry));
            result = true;
        } catch (LdapException | LDAPUtilException e) {
            debug.error("Unable to create an authenticator entry with {}", authenticator.getCredentialID(), e);
        } finally {
            IOUtils.closeIfNotNull(conn);
        }
        return result;
    }

    /**
     * Get authenticators associated with userID.
     * 
     * @param userID The user handle of the user account entity.
     * @return A collection of authenticators associated with userID.
     */
    public Set<WebAuthnAuthenticator> getAuthenticators(byte[] userID) {
        Set<WebAuthnAuthenticator> authenticators = new HashSet<WebAuthnAuthenticator>();
        if (!isValid()) {
            debug.error("AuthenticatorWebAuthnService in {} realm is invalid.", realm);
            return authenticators;
        }
        SearchScope scope = SearchScope.SINGLE_LEVEL;
        String userIDStr = WebAuthnAuthenticator.getUserIDAsString(userID);
        Filter searchFilter =
                Filter.valueOf(useridAttrName + "=" + userIDStr);
        for (String className : classNames) {
            Filter objectClassFilter = Filter.valueOf("objectClass"+ "=" + className);
            searchFilter = Filter.and(searchFilter, objectClassFilter);
        }
        SearchRequest searchRequest =
                LDAPRequests.newSearchRequest(DN.valueOf(baseDN), scope, searchFilter,
                        new String[]{credentialAttrName, keyAttrName, counterAttrName,
                                credentialNameAttrName, WebAuthnAuthenticator.TIMESTAMP_ATTR_NAME});
        Connection conn = null;
        try {
            conn = getConnection();
            ConnectionEntryReader reader = conn.search(searchRequest);
            while (reader.hasNext()) {
                WebAuthnAuthenticator authenticator = new WebAuthnAuthenticator();
                authenticator.setUserID(userID);
                if (reader.isEntry()) {
                    SearchResultEntry entry = reader.readEntry();
                    Attribute attribute = entry.getAttribute(credentialAttrName);
                    authenticator.setCredentialID(attribute.firstValue().toString());
                    attribute = entry.getAttribute(keyAttrName);
                    authenticator.setPublicKey(attribute.firstValue().toByteArray());
                    attribute = entry.getAttribute(counterAttrName);
                    authenticator.setSignCount(Long.valueOf(attribute.firstValue().toString()));
                    attribute = entry.getAttribute(credentialNameAttrName);
                    authenticator.setCredentialName(attribute.firstValue().toString());
                    Date timestamp = entry.parseAttribute(WebAuthnAuthenticator.TIMESTAMP_ATTR_NAME)
                            .asGeneralizedTime().toDate();
                    authenticator.setCreateTimestamp(timestamp);
                    authenticators.add(authenticator);
                } else {
                    //ignore search result references
                    reader.readReference();
                }
            }
        } catch (LdapException | LDAPUtilException | SearchResultReferenceIOException e) {
            debug.error("Unable to search authenticator entries with {}", userIDStr, e);
        } finally {
            IOUtils.closeIfNotNull(conn);
        }
        return authenticators;
    }

    /**
     * Update the signature counter.
     * 
     * @param authenticator The target authenticator.
     * @return Returns true if the entry is successfully saved.
     */
    public boolean updateCounter(WebAuthnAuthenticator authenticator) {
        boolean result = false;
        if (!isValid()) {
            debug.error("AuthenticatorWebAuthnService in {} realm is invalid.", realm);
            return result;
        }
        String dn = DN.valueOf(baseDN)
                .child(credentialAttrName, authenticator.getCredentialID()).toString();
        ModifyRequest modifyRequest = LDAPRequests.newModifyRequest(dn);
        modifyRequest.addModification(
                ModificationType.REPLACE, counterAttrName, authenticator.getSignCount());

        Connection conn = null;
        try {
            conn = getConnection();
            conn.modify(modifyRequest);
            result = true;
        } catch (LdapException | LDAPUtilException e) {
            debug.error("Unable to update the signature counter with {}", authenticator.getCredentialID(), e);
        } finally {
            IOUtils.closeIfNotNull(conn);
        }
        return result;
    }

    /**
     * Update the Credential Name.
     * 
     * @param authenticator The target authenticator.
     * @return Returns true if the entry is successfully saved.
     */
    public boolean storeCredentialName(WebAuthnAuthenticator authenticator) {
        boolean result = false;
        if (!isValid()) {
            debug.error("AuthenticatorWebAuthnService in {} realm is invalid.", realm);
            return result;
        }
        String dn = DN.valueOf(baseDN)
                .child(credentialAttrName, authenticator.getCredentialID()).toString();
        ModifyRequest modifyRequest = LDAPRequests.newModifyRequest(dn);
        modifyRequest.addModification(
                ModificationType.REPLACE, credentialNameAttrName, authenticator.getCredentialName());

        Connection conn = null;
        try {
            conn = getConnection();
            conn.modify(modifyRequest);
            result = true;
        } catch (LdapException | LDAPUtilException e) {
            debug.error("Unable to update the Credential Name with {}", authenticator.getCredentialID(), e);
        } finally {
            IOUtils.closeIfNotNull(conn);
        }
        return result;
    }

    /**
     * Delete an authenticator.
     * 
     * @param credentialID The Credential ID.
     * @return Returns true if the entry is successfully deleted.
     */
    public boolean deleteAuthenticator(String credentialID) {
        boolean result = false;
        if (!isValid()) {
            debug.error("AuthenticatorWebAuthnService in {} realm is invalid.", realm);
            return result;
        }
        String dn = DN.valueOf(baseDN)
                .child(credentialAttrName, credentialID).toString();
        Connection conn = null;
        try {
            conn = getConnection();
            conn.delete(dn);
            result = true;
        } catch (LdapException | LDAPUtilException e) {
            debug.error("Unable to delete an authenticator entry with {}", credentialID, e);
        } finally {
            IOUtils.closeIfNotNull(conn);
        }
        return result;
    }

    /**
     * Close connection pool.
     */
    public void close() {
        synchronized(this) {
            if (cPool != null) {
                cPool.close();
                cPool = null;
            }
        }
    }

    @Override
    public String getConfigStorageAttributeName() {
        return null;
    }

    @Override
    public DeviceSerialisation getDeviceSerialisationStrategy() {
        return null;
    }

}
