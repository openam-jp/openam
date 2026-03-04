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
package jp.co.osstech.openam.core.rest.sms;

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newResourceResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.xml.namespace.QName;

import org.forgerock.guava.common.collect.Sets;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.annotations.RequestHandler;
import org.forgerock.openam.core.rest.sms.SmsJsonConverter;
import org.forgerock.openam.shared.sts.SharedSTSConstants;
import org.forgerock.openam.sts.InstanceConfigMarshaller;
import org.forgerock.openam.sts.STSPublishException;
import org.forgerock.openam.sts.publish.config.STSPublishInjectorHolder;
import org.forgerock.openam.sts.publish.soap.SoapSTSInstancePublisher;
import org.forgerock.openam.sts.soap.config.user.SoapSTSInstanceConfig;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.Context;

import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;

/**
 * REST resource for SOAP STS Management.
 */
@RequestHandler
public class SoapSTSResourceProvider extends STSResourceProviderBase {

    public static final String TYPE = "soap";

    /*
     * The following three strings must match the prefixes of possible selections in the
     * security-policy-validated-token-config property. The values are used to ensure congruence between the
     * selected wsdl file, and the security-policy-validated-token-config selection.
     */
    private static final String OPENAM_SUPPORTING_TOKEN = "OPENAM";
    private static final String USERNAME_SUPPORTING_TOKEN = "USERNAME";
    private static final String X509_SUPPORTING_TOKEN = "X509";

    /*
     * The following three strings must match the SupportingToken identifier in the .wsdl file definitions in the
     * deployment-wsdl-location property. The values are used to ensure congruence between the selected wsdl file,
     * and the security-policy-validated-token-config selection.
     */
    private static final String USERNAME_SUPPORTING_WSDL_FILE_NAME_CONSTITUENT = "sts_ut";
    private static final String X509_SUPPORTING_WSDL_FILE_NAME_CONSTITUENT = "sts_x509";
    private static final String OPENAM_SUPPORTING_WSDL_FILE_NAME_CONSTITUENT = "sts_am";

    private static final String SOAP_KEYSTORE_FILENAME = "soap-keystore-filename";
    private static final String SOAP_KEYSTORE_PASSWORD = "soap-keystore-password";

    private final SoapSTSInstancePublisher publisher;
    private final InstanceConfigMarshaller<SoapSTSInstanceConfig> instanceConfigMarshaller;

    @Inject
    public SoapSTSResourceProvider(@Assisted SmsJsonConverter converter, @Assisted ServiceSchema schema,
            @Assisted SchemaType type, @Assisted List<ServiceSchema> subSchemaPath, @Assisted String uriPath,
            @Assisted boolean serviceHasInstanceName, @Named("frRest") Debug debug,
            @Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache,
            @Named("DefaultLocale") Locale defaultLocale) {
        super(schema, type, subSchemaPath, uriPath, serviceHasInstanceName, converter, debug, resourceBundleCache,
                defaultLocale);
        this.publisher = STSPublishInjectorHolder.getInstance(Key.get(SoapSTSInstancePublisher.class));
        this.instanceConfigMarshaller = STSPublishInjectorHolder.getInstance(Key.get(new TypeLiteral<InstanceConfigMarshaller<SoapSTSInstanceConfig>>() {}));
    }

    @Override
    protected void createSTSInstance(Map<String, Set<String>> attributes)
            throws STSPublishException, InternalServerErrorException {
        SoapSTSInstanceConfig instanceConfig = instanceConfigMarshaller.fromMapAttributes(attributes);
        publisher.publishInstance(instanceConfig);
    }

    @Override
    protected JsonValue readSTSInstance(String realm, String resourceId, Context context)
            throws STSPublishException, InternalServerErrorException {
        String internalId = getInternalId(realm, resourceId);
        SoapSTSInstanceConfig instanceConfig = publisher.getPublishedInstance(internalId, realm);
        return configToJsonValue(realm, resourceId, context, instanceConfig);
    }

    @Override
    protected void updateSTSInstance(String realm, String resourceId, Map<String, Set<String>> attributes)
            throws STSPublishException, InternalServerErrorException {
        String internalId = getInternalId(realm, resourceId);
        SoapSTSInstanceConfig newInstanceConfig = instanceConfigMarshaller.fromMapAttributes(attributes);
        publisher.removeInstance(internalId, realm);
        publisher.publishInstance(newInstanceConfig);
    }

    @Override
    protected void deleteSTSInstance(String realm, String resourceId) throws STSPublishException {
        String internalId = getInternalId(realm, resourceId);
        publisher.removeInstance(internalId, realm);
    }

    @Override
    protected Map<String, Set<String>> getAttributesForUpdate(String realm, String resourceId,
            Map<String, Set<String>> requestAttributes) throws STSPublishException, BadRequestException {
        String internalId = getInternalId(realm, resourceId);
        SoapSTSInstanceConfig instanceConfig = publisher.getPublishedInstance(internalId, realm);
        Map<String, Set<String>> attributes = instanceConfig.marshalToAttributeMap();
        mergeAttributes(attributes, requestAttributes);
        return attributes;
    }

    @Override
    protected List<ResourceResponse> getResourcesInRealm(String realm, Context context)
            throws STSPublishException, InternalServerErrorException {
        List<ResourceResponse> results = new ArrayList<>();
        List<SoapSTSInstanceConfig> publishedInstances = publisher.getPublishedInstances();
        for (SoapSTSInstanceConfig config : publishedInstances) {
            if (realm.equals(config.getDeploymentConfig().getRealm())) {
                String resourceId = config.getDeploymentConfig().getUriElement();
                JsonValue value = configToJsonValue(realm, resourceId, context, config);
                results.add(newResourceResponse(resourceId, "0", value));
            }
        }
        return results;
    }

    @Override
    protected boolean exists(String realm, String resourceId) throws STSPublishException {
        List<SoapSTSInstanceConfig> publishedInstances = publisher.getPublishedInstances();
        for (SoapSTSInstanceConfig config : publishedInstances) {
            if (realm.equals(config.getDeploymentConfig().getRealm())
                    && resourceId.equals(config.getDeploymentConfig().getUriElement())) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void validateStsTypeSpecificConfiguration(Map<String, Set<String>> attributes) throws BadRequestException {
        if (customWsdlFileLocationEntered(attributes) ^ customWsdlFileSelectedFromDropDown(attributes)) {
            throw new BadRequestException("If a custom wsdl file location is specified,"
                    + " then the Custom wsdl file entry must be selected from the Wsdl File Referencing Security Policy Binding Selection list");
        }
        if (!customWsdlFileLocationEntered(attributes) &&
                CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.WSDL_LOCATION))) {
            throw new BadRequestException("Either a custom wsdl file must be specified,"
                    + " or a entry in the Wsdl File Referencing Security Policy Binding Selection list must be selected");
        }
        if (customWsdlSpecified(attributes)) {
            if (CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.CUSTOM_SERVICE_QNAME)) ||
                        CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.CUSTOM_PORT_QNAME))) {
                throw new BadRequestException("If a custom wsdl file location is specified,"
                        + " then the custom service name and custom service port must also be specified");
            } else {
                if (!stringInQNameFormat(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.CUSTOM_SERVICE_QNAME)) ||
                        !stringInQNameFormat(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.CUSTOM_PORT_QNAME))) {
                    throw new BadRequestException("Both the custom service name and port must be in QName format: {namespace}local_name");
                }
            }
        }

        /*
         * For standard wsdl locations, ensure congruence between the selected wsdl and the single entry in
         * the SecurityPolicy validated token configuration
         */
        if (!customWsdlSpecified(attributes)) {
            final Set<String> securityPolicyValidatedTokenSet = attributes.get(SharedSTSConstants.SECURITY_POLICY_VALIDATED_TOKEN_CONFIG);
            if (securityPolicyValidatedTokenSet.size() != 1) {
                throw new BadRequestException("When no custom wsdl file location is specified,"
                        + " only a single entry in the Security Policy Validated Token list can be selected.");
            } else {
                /*
                This value will correspond to one of the possible selections defined in soapSTS.xml under the
                security-policy-validated-token-config property
                 */
                final String supportingToken = securityPolicyValidatedTokenSet.iterator().next();
                final String wsdlLocation = CollectionHelper.getMapAttr(attributes, SharedSTSConstants.WSDL_LOCATION);
                ensureCongruenceBetweenWsdlLocationAndSupportingToken(supportingToken, wsdlLocation);
            }
        }
        /*
         * if delegation relationship is supported, either out-of-the-box or custom validators have to be specified.
         */
        boolean delegationSupported = Boolean.parseBoolean(
                CollectionHelper.getMapAttr(attributes, SharedSTSConstants.DELEGATION_RELATIONSHIP_SUPPORTED));
        if (delegationSupported) {
            if (CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.DELEGATION_TOKEN_VALIDATORS)) &&
                    CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.CUSTOM_DELEGATION_TOKEN_HANDLERS))) {
                throw new BadRequestException("If the Delegation Relationships Supported check-box is selected"
                        + " then either Custom Delegation Handler(s) must be specified or Delegated Token Types must be selected");
            }
        }

        // If SOAP Keystore Location is specified, Keystore Password is also required
        if (StringUtils.isNotEmpty(CollectionHelper.getMapAttr(attributes, SOAP_KEYSTORE_FILENAME))
                && StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SOAP_KEYSTORE_PASSWORD))) {
            throw new BadRequestException("If SOAP Keystore Location is specified, Keystore Password is also required");
        }
    }

    @Override
    protected Set<String> getSupportedTokenTypes(Map<String, Set<String>> attributes) {
        return attributes.get("issued-token-types");
    }

    @Override
    protected void addStsTypeSpecificInternalConfiguration(Map<String, Set<String>> attributes) {
        /*
         * For standard wsdl locations, the service name and port must be filled-in. As a courtesy to the user,
         * these options won't be displayed in the AdminUI, as they are standard to all pre-packaged wsdl files.
         * This logic block will fill in these standard values.
        */
        if (!customWsdlSpecified(attributes)) {
            attributes.put(SharedSTSConstants.SERVICE_QNAME, Sets.newHashSet(SharedSTSConstants.STANDARD_STS_SERVICE_QNAME.toString()));
            attributes.put(SharedSTSConstants.PORT_QNAME, Sets.newHashSet(SharedSTSConstants.STANDARD_STS_PORT_QNAME.toString()));
        }
    }

    @Override
    protected String getTokenTypeAttributeTitle() {
        return "Issued Tokens";
    }

    private JsonValue configToJsonValue(String realm, String resourceId, Context context,
            SoapSTSInstanceConfig instanceConfig)
                    throws InternalServerErrorException {
        JsonValue value = json(object());

        Map<String, Set<String>> attributes = instanceConfig.marshalToAttributeMap();
        converter.toJson(realm, attributes, false, value);

        value.add(ResourceResponse.FIELD_CONTENT_ID, resourceId);
        try {
            JsonValue type = getTypeValue(context).put(ResourceResponse.FIELD_CONTENT_ID, TYPE);
            value.add("_type", type.getObject());
        } catch (SSOException | SMSException e) {
            throw new InternalServerErrorException();
        }

        return value;
    }

    private boolean customWsdlFileSelectedFromDropDown(Map<String, Set<String>> configurationState) {
        return SharedSTSConstants.CUSTOM_WSDL_FILE_INDICATOR.equals(CollectionHelper.getMapAttr(configurationState, SharedSTSConstants.WSDL_LOCATION));
    }

    private boolean customWsdlFileLocationEntered(Map<String, Set<String>> configurationState) {
        return CollectionUtils.isNotEmpty(configurationState.get(SharedSTSConstants.CUSTOM_WSDL_LOCATION));
    }

    private boolean customWsdlSpecified(Map<String, Set<String>> configurationState) {
        return customWsdlFileLocationEntered(configurationState) && customWsdlFileSelectedFromDropDown(configurationState);
    }

    private boolean stringInQNameFormat(String customPortOrServiceName) {
        try {
            QName.valueOf(customPortOrServiceName);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private void ensureCongruenceBetweenWsdlLocationAndSupportingToken(String supportingToken, String wsdlLocation)
            throws BadRequestException {
        String message ="The entry selected from the Wsdl File Referencing Security Policy Binding Selection list,"
                + " and the element selected from Security Policy Validated Token must both reference the same token type";

        /*
         * The wsdlLocation will be one of the wsdl locations (besides custom) defined in the deployment-wsdl-location
         * property. The supportingToken string will be a non-null, non-empty string selected from the
         * security-policy-validated-token-config list.
         */
        if (supportingToken.startsWith(OPENAM_SUPPORTING_TOKEN)) {
            if (!wsdlLocation.startsWith(OPENAM_SUPPORTING_WSDL_FILE_NAME_CONSTITUENT)) {
                throw new BadRequestException(message);
            }
        } else if (supportingToken.startsWith(X509_SUPPORTING_TOKEN)) {
            if (!wsdlLocation.startsWith(X509_SUPPORTING_WSDL_FILE_NAME_CONSTITUENT)) {
                throw new BadRequestException(message);
            }
        } else if (supportingToken.startsWith(USERNAME_SUPPORTING_TOKEN)) {
            if (!wsdlLocation.startsWith(USERNAME_SUPPORTING_WSDL_FILE_NAME_CONSTITUENT)) {
                throw new BadRequestException(message);
            }
        } else {
            throw new BadRequestException(message);
        }
    }
}
