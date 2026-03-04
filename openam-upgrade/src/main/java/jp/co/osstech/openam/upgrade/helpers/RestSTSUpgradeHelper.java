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
package jp.co.osstech.openam.upgrade.helpers;

import org.forgerock.openam.shared.sts.SharedSTSConstants;
import org.forgerock.openam.upgrade.UpgradeException;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;

import com.sun.identity.sm.AbstractUpgradeHelper;
import com.sun.identity.sm.AttributeSchemaImpl;

/**
 * This upgrade helper adjusts RestSecurityTokenService schema.
 */
public class RestSTSUpgradeHelper extends AbstractUpgradeHelper {

    private static final String PERSIST_ISSUED_TOKENS_IN_CTS = "persist-issued-tokens-in-cts";
    private static final String DEPLOYMENT_AUTH_TARGET_MAPPINGS = "deployment-auth-target-mappings";
    private static final String SAML2_NAME_ID_FORMAT = "saml2-name-id-format";
    private static final String SAML2_CUSTOM_CONDITIONS_PROVIDER_CLASS = "saml2-custom-conditions-provider-class-name";
    private static final String SAML2_CUSTOM_SUBJECT_PROVIDER_CLASS = "saml2-custom-subject-provider-class-name";
    private static final String SAML2_CUSTOM_AUTHENTICATION_STATEMENTS_PROVIDER_CLASS = "saml2-custom-authentication-statements-provider-class-name";
    private static final String SAML2_CUSTOM_ATTRIBUTE_STATEMENTS_PROVIDER_CLASS = "saml2-custom-attribute-statements-provider-class-name";
    private static final String SAML2_CUSTOM_AUTHZ_DECISION_STATEMENTS_PROVIDER_CLASS = "saml2-custom-authz-decision-statements-provider-class-name";
    private static final String SAML2_CUSTOM_ATTRIBUTE_MAPPER_CLASS = "saml2-custom-attribute-mapper-class-name";
    private static final String SAML2_CUSTOM_AUTHN_CONTEXT_MAPPER_CLASS = "saml2-custom-authn-context-mapper-class-name";
    private static final String OIDC_PUBLIC_KEY_REFERENCE_TYPE = "oidc-public-key-reference-type";
    private static final String OIDC_AUTHORIZED_PARTY = "oidc-authorized-party";
    private static final String OIDC_CUSTOM_CLAIM_MAPPER_CLASS = "oidc-custom-claim-mapper-class";
    private static final String OIDC_CUSTOM_AUTHN_CONTEXT_MAPPER_CLASS = "oidc-custom-authn-context-mapper-class";
    private static final String OIDC_CUSTOM_AUTHN_METHOD_REFERENCES_MAPPER_CLASS = "oidc-custom-authn-method-references-mapper-class";

    public RestSTSUpgradeHelper() {
        attributes.add(PERSIST_ISSUED_TOKENS_IN_CTS);
        attributes.add(SharedSTSConstants.SUPPORTED_TOKEN_TRANSFORMS);
        attributes.add(SharedSTSConstants.CUSTOM_TOKEN_VALIDATORS);
        attributes.add(SharedSTSConstants.CUSTOM_TOKEN_PROVIDERS);
        attributes.add(SharedSTSConstants.CUSTOM_TOKEN_TRANSFORMS);
        attributes.add(SharedSTSConstants.DEPLOYMENT_REALM);
        attributes.add(SharedSTSConstants.DEPLOYMENT_URL_ELEMENT);
        attributes.add(DEPLOYMENT_AUTH_TARGET_MAPPINGS);
        attributes.add(SharedSTSConstants.OFFLOADED_TWO_WAY_TLS_HEADER_KEY);
        attributes.add(SharedSTSConstants.TLS_OFFLOAD_ENGINE_HOSTS);
        attributes.add(SAML2_NAME_ID_FORMAT);
        attributes.add(SharedSTSConstants.ISSUER_NAME);
        attributes.add(SharedSTSConstants.SAML2_TOKEN_LIFETIME);
        attributes.add(SAML2_CUSTOM_CONDITIONS_PROVIDER_CLASS);
        attributes.add(SAML2_CUSTOM_SUBJECT_PROVIDER_CLASS);
        attributes.add(SAML2_CUSTOM_AUTHENTICATION_STATEMENTS_PROVIDER_CLASS);
        attributes.add(SAML2_CUSTOM_ATTRIBUTE_STATEMENTS_PROVIDER_CLASS);
        attributes.add(SAML2_CUSTOM_AUTHZ_DECISION_STATEMENTS_PROVIDER_CLASS);
        attributes.add(SAML2_CUSTOM_ATTRIBUTE_MAPPER_CLASS);
        attributes.add(SAML2_CUSTOM_AUTHN_CONTEXT_MAPPER_CLASS);
        attributes.add(SharedSTSConstants.SAML2_SIGN_ASSERTION);
        attributes.add(SharedSTSConstants.SAML2_SP_ENTITY_ID);
        attributes.add(SharedSTSConstants.SAML2_SP_ACS_URL);
        attributes.add(SharedSTSConstants.SAML2_ENCRYPT_ATTRIBUTES);
        attributes.add(SharedSTSConstants.SAML2_ENCRYPT_ASSERTION);
        attributes.add(SharedSTSConstants.SAML2_ENCRYPT_NAME_ID);
        attributes.add(SharedSTSConstants.SAML2_ENCRYPTION_ALGORITHM);
        attributes.add(SharedSTSConstants.SAML2_ENCRYPTION_ALGORITHM_STRENGTH);
        attributes.add(SharedSTSConstants.SAML2_KEYSTORE_FILE_NAME);
        attributes.add(SharedSTSConstants.SAML2_KEYSTORE_PASSWORD);
        attributes.add(SharedSTSConstants.SAML2_ENCRYPTION_KEY_ALIAS);
        attributes.add(SharedSTSConstants.SAML2_SIGNATURE_KEY_ALIAS);
        attributes.add(SharedSTSConstants.SAML2_SIGNATURE_KEY_PASSWORD);
        attributes.add(SharedSTSConstants.SAML2_ATTRIBUTE_MAP);
        attributes.add(SharedSTSConstants.OIDC_ISSUER);
        attributes.add(SharedSTSConstants.OIDC_TOKEN_LIFETIME);
        attributes.add(SharedSTSConstants.OIDC_SIGNATURE_ALGORITHM);
        attributes.add(OIDC_PUBLIC_KEY_REFERENCE_TYPE);
        attributes.add(SharedSTSConstants.OIDC_KEYSTORE_LOCATION);
        attributes.add(SharedSTSConstants.OIDC_KEYSTORE_PASSWORD);
        attributes.add(SharedSTSConstants.OIDC_SIGNATURE_KEY_ALIAS);
        attributes.add(SharedSTSConstants.OIDC_SIGNATURE_KEY_PASSWORD);
        attributes.add(SharedSTSConstants.OIDC_CLIENT_SECRET);
        attributes.add(SharedSTSConstants.OIDC_AUDIENCE);
        attributes.add(OIDC_AUTHORIZED_PARTY);
        attributes.add(SharedSTSConstants.OIDC_CLAIM_MAP);
        attributes.add(OIDC_CUSTOM_CLAIM_MAPPER_CLASS);
        attributes.add(OIDC_CUSTOM_AUTHN_CONTEXT_MAPPER_CLASS);
        attributes.add(OIDC_CUSTOM_AUTHN_METHOD_REFERENCES_MAPPER_CLASS);
    }

    @Override
    public AttributeSchemaImpl upgradeAttribute(AttributeSchemaImpl oldAttr, AttributeSchemaImpl newAttr)
            throws UpgradeException {
        if (!StringUtils.isEqualTo(oldAttr.getI18NKey(), newAttr.getI18NKey())) {
            return newAttr;
        } else if (!CollectionUtils.genericCompare(oldAttr.getOrder(), newAttr.getOrder())) {
            return newAttr;
        } else if (oldAttr.getType() != newAttr.getType()) {
            return newAttr;
        } else if (!CollectionUtils.genericCompare(oldAttr.getDefaultValues(), newAttr.getDefaultValues())) {
            return newAttr;
        } else if (!StringUtils.isEqualTo(oldAttr.getValidator(), newAttr.getValidator())) {
            return newAttr;
        }
        return null;
    }
}
