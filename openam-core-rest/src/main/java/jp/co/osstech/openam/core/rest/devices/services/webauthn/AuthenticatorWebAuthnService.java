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
* Copyright 2019 Open Source Solution Technology Corporation
*/
package jp.co.osstech.openam.core.rest.devices.services.webauthn;

import com.iplanet.sso.SSOException;
import com.sun.identity.common.ShutdownManager;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.forgerock.openam.core.rest.devices.DeviceSerialisation;
import org.forgerock.openam.core.rest.devices.services.DeviceService;
import org.forgerock.openam.ldap.LDAPRequests;
import org.forgerock.openam.ldap.LDAPURL;
import org.forgerock.openam.ldap.LDAPUtils;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.ConnectionFactory;
import org.forgerock.opendj.ldap.Connections;
import org.forgerock.opendj.ldap.DN;
import org.forgerock.opendj.ldap.Entry;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LdapException;
import org.forgerock.opendj.ldap.LinkedHashMapEntry;
import org.forgerock.opendj.ldap.SSLContextBuilder;
import org.forgerock.opendj.ldap.TrustManagers;
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

    private static final String WEBAUTHN_CLASS_NAME = 
            "openam-auth-webauthn-objectclass-name";
    private static final String WEBAUTHN_CREDENTIAL_ATTRIBUTE_NAME = 
            "openam-auth-webauthn-credentialid-attribute-name";
    private static final String WEBAUTHN_KEY_ATTRIBUTE_NAME = 
            "openam-auth-webauthn-key-attribute-name";
    private static final String WEBAUTHN_DISPLAYNAME_ATTRIBUTE_NAME = 
            "openam-auth-webauthn-displayname-attribute-name";
    private static final String WEBAUTHN_COUNTER_ATTRIBUTE_NAME = 
            "openam-auth-webauthn-counter-attribute-name";
    
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

    private final static int MIN_CONNECTION_POOL_SIZE = 1;
    private final static int MAX_CONNECTION_POOL_SIZE = 10;
    
    final private Debug debug;
    private Map<String, Set<?>> options;
    private String className = null;
    private String credentialAttrName = null;
    private String keyAttrName = null;
    private String displayNameAttrName = null;
    private String counterAttrName = null;
    private String baseDN = null;
    private ConnectionFactory cPool = null;
    
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

        try {
            ServiceConfig scm = configManager.getOrganizationConfig(realm, null);
            options = scm.getAttributes();

            baseDN = CollectionHelper.getServerMapAttr(options, WEBAUTHN_LDAP_BASE_DN);
            if (baseDN == null) {
                debug.error("BaseDN for search was null");
            }
            
            className = CollectionHelper.getServerMapAttr(options, WEBAUTHN_CLASS_NAME);
            credentialAttrName = CollectionHelper.getServerMapAttr(options, WEBAUTHN_CREDENTIAL_ATTRIBUTE_NAME);
            keyAttrName = CollectionHelper.getServerMapAttr(options, WEBAUTHN_KEY_ATTRIBUTE_NAME);
            displayNameAttrName = CollectionHelper.getServerMapAttr(options, WEBAUTHN_DISPLAYNAME_ATTRIBUTE_NAME);
            counterAttrName = CollectionHelper.getServerMapAttr(options, WEBAUTHN_COUNTER_ATTRIBUTE_NAME);
            
        } catch (SMSException | SSOException e) {
            if (debug.errorEnabled()) {
                debug.error("Error connecting to SMS to retrieve config for AuthenticatorWebAuthnService.", e);
            }
            throw e;
        }
    }
    
    public void initializeConnection() {
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

        
        try {
            Options options = Options.defaultOptions()
                    .set(LDAPConnectionFactory.REQUEST_TIMEOUT, 
                            new Duration((long) operationTimeout, TimeUnit.SECONDS));
        
            int min = MIN_CONNECTION_POOL_SIZE;
            int max = MAX_CONNECTION_POOL_SIZE;
            if (min >= max) {
                min = max - 1;
            }
        
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
                    bindPassword, max, heartBeatInterval, heartBeatTimeUnit, options);
            if (secondaryServers.isEmpty()) {
                cPool = primaryCf;
            } else {
                ConnectionFactory secondaryCf = LDAPUtils.newFailoverConnectionPool(secondaryUrls, bindDN,
                        bindPassword, max, heartBeatInterval, heartBeatTimeUnit, options);
                cPool = Connections.newFailoverLoadBalancer(CollectionUtils.asList(primaryCf, secondaryCf), options);
            }

            ShutdownManager shutdownMan = com.sun.identity.common.ShutdownManager.getInstance();
            shutdownMan.addShutdownListener(new ShutdownListener() {
                public void shutdown() {
                    cPool.close();
                }
            });
            
        } catch (GeneralSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    private synchronized Connection getConnection() throws LdapException {
        if (cPool == null) {
        	initializeConnection();
        }
        return cPool.getConnection();
    }

    /**
     * 
     * @param credentialId
     * @param publicKey
     * @param counter
     * @return
     */
    public boolean createAuthenticator(String credentialId, byte[] publicKey, String counter,
            byte[] entryUUID) {
    	String dn = DN.valueOf(baseDN).child(credentialAttrName ,credentialId).toString();
    	Entry entry = new LinkedHashMapEntry(dn);
    	Set<String> objectClasses = CollectionUtils.asSet(className);
    	entry.addAttribute("objectClass", objectClasses.toArray());
    	entry.addAttribute(credentialAttrName, credentialId);
    	entry.addAttribute(keyAttrName, publicKey);
    	entry.addAttribute(counterAttrName, counter);
    	entry.addAttribute("fido2UserID", entryUUID);
    	
    	try {
			Connection conn = getConnection();
			conn.add(LDAPRequests.newAddRequest(entry));
		} catch (LdapException e) {
			e.printStackTrace();
		}
    	return false;
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
