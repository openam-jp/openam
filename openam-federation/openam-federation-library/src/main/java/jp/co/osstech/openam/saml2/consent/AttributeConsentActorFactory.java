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

import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.utils.AMKeyProvider;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.saml2.plugins.IDPAttributeMapper;
import com.sun.identity.saml2.profile.IDPSSOUtil;
import com.sun.identity.saml2.profile.ServerFaultException;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

/**
 * The class <code>AttributeConsentActorFactory</code> generate class instances
 * used in SAML2 attribute consent step.
 */
public class AttributeConsentActorFactory {
    private static final String AUTH_SERVICE_NAME = "iPlanetAMAuthService";
    private static final String AUTH_KEY_ALIAS = "iplanet-am-auth-key-alias";
    private static final String SIGNING_SHARED_SECRET = "iplanet-am-auth-hmac-signing-shared-secret";

    public AttributeConsentActorFactory() {

    }

    /**
     * Create <code>AttributeConsentStep</code> instance given realm, idp and sp.
     *
     * @param realm       The name of the realm.
     * @param idpEntityId The entity id of the idp.
     * @param spEntityId  The entity id of the sp.
     * @return <code>AttributeConsentStep</code> instance.
     * @throws SAML2Exception
     * @throws SSOException
     * @throws SMSException
     * @throws ServerFaultException
     */
    public AttributeConsentStep getConsentStep(String realm, String idpEntityId, String spEntityId)
            throws SAML2Exception, SSOException, SMSException, ServerFaultException {
        boolean spEnabledConsent = Boolean.parseBoolean(SAML2Utils.getAttributeValueFromSSOConfig(realm, spEntityId,
                SAML2Constants.SP_ROLE, SAML2Constants.SP_ENABLE_ATTRIBUTE_CONSENT));

        if (!spEnabledConsent) {
            return new DisabledAttributeConsentStepImpl();
        }

        IDPAttributeMapper mapper = getMapper(realm, idpEntityId);
        IDPAttributeConsentConfig config = getIdpConsentConfig(realm, idpEntityId);
        AttributeConsentHistorySerializer serializer = getSerializer(realm);
        ConsentAuditor auditor = InjectorHolder.getInstance(ConsentAuditor.class);
        if (serializer == null) {
            throw new ServerFaultException("invalidConfiguration", "Consent configuration is invalid");
        }
        return new AttributeConsentStepImpl(realm, idpEntityId, spEntityId, mapper, config, serializer,
                auditor);
    }

    private IDPAttributeConsentConfig getIdpConsentConfig(String realm, String idpEntityId) {
        List<String> config = SAML2Utils.getAllAttributeValueFromSSOConfig(realm, idpEntityId,
                SAML2Constants.IDP_ROLE, SAML2Constants.IDP_CONSENT_REQUIRED_ATTRIBUTE);
        return new IDPAttributeConsentConfig(config);
    }

    private AttributeConsentHistorySerializer getSerializer(String realm) throws SMSException, SSOException {
        AMKeyProvider keyProvider = new AMKeyProvider();
        String keyAlias = getKeyAlias(realm);
        PublicKey publicKey = keyProvider.getPublicKey(keyAlias);
        PrivateKey privateKey = keyProvider.getPrivateKey(keyAlias);
        if (publicKey == null || privateKey == null) {
            return null;
        }
        String signingSecret = getSigningSecret(realm);
        if (signingSecret == null) {
            return null;
        }
        return new AttributeConsentHistorySerializer(publicKey, privateKey, signingSecret);
    }

    private String getKeyAlias(String realm) throws SMSException, SSOException {
        SSOToken adminToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
        ServiceConfigManager scm = new ServiceConfigManager(AUTH_SERVICE_NAME, adminToken);
        ServiceConfig realmConfig = scm.getOrganizationConfig(realm, null);
        return CollectionHelper.getMapAttr(realmConfig.getAttributes(), AUTH_KEY_ALIAS);
    }

    private String getSigningSecret(String realm) throws SSOException, SMSException {
        SSOToken adminToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
        ServiceConfigManager scm = new ServiceConfigManager(AUTH_SERVICE_NAME, adminToken);
        ServiceConfig realmConfig = scm.getOrganizationConfig(realm, null);
        return CollectionHelper.getMapAttr(realmConfig.getAttributes(), SIGNING_SHARED_SECRET);
    }

    IDPAttributeMapper getMapper(String realm, String idpEntityId) throws SAML2Exception {
        return IDPSSOUtil.getIDPAttributeMapper(realm, idpEntityId);
    }

}
