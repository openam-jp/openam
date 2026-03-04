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

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.annotations.RequestHandler;
import org.forgerock.openam.core.rest.sms.SmsJsonConverter;
import org.forgerock.openam.shared.sts.SharedSTSConstants;
import org.forgerock.openam.sts.InstanceConfigMarshaller;
import org.forgerock.openam.sts.STSPublishException;
import org.forgerock.openam.sts.config.user.CustomTokenOperation;
import org.forgerock.openam.sts.publish.config.STSPublishInjectorHolder;
import org.forgerock.openam.sts.publish.rest.RestSTSInstancePublisher;
import org.forgerock.openam.sts.rest.RestSTS;
import org.forgerock.openam.sts.rest.config.RestSTSInstanceModule;
import org.forgerock.openam.sts.rest.config.user.RestSTSInstanceConfig;
import org.forgerock.openam.sts.rest.config.user.TokenTransformConfig;
import org.forgerock.openam.sts.rest.token.provider.RestTokenProvider;
import org.forgerock.openam.sts.rest.token.validator.RestTokenTransformValidator;
import org.forgerock.services.context.Context;

import com.google.inject.Guice;
import com.google.inject.Injector;
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
 * REST resource for REST STS Management.
 */
@RequestHandler
public class RestSTSResourceProvider extends STSResourceProviderBase {

    public static final String TYPE = "rest";

    private final RestSTSInstancePublisher publisher;
    private final InstanceConfigMarshaller<RestSTSInstanceConfig> instanceConfigMarshaller;

    @Inject
    public RestSTSResourceProvider(@Assisted SmsJsonConverter converter, @Assisted ServiceSchema schema,
            @Assisted SchemaType type, @Assisted List<ServiceSchema> subSchemaPath, @Assisted String uriPath,
            @Assisted boolean serviceHasInstanceName, @Named("frRest") Debug debug,
            @Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache,
            @Named("DefaultLocale") Locale defaultLocale) {
        super(schema, type, subSchemaPath, uriPath, serviceHasInstanceName, converter, debug, resourceBundleCache,
                defaultLocale);
        this.publisher = STSPublishInjectorHolder.getInstance(Key.get(RestSTSInstancePublisher.class));
        this.instanceConfigMarshaller = STSPublishInjectorHolder.getInstance(Key.get(new TypeLiteral<InstanceConfigMarshaller<RestSTSInstanceConfig>>() {}));
    }

    @Override
    protected void createSTSInstance(Map<String, Set<String>> attributes)
            throws STSPublishException, InternalServerErrorException {
        RestSTSInstanceConfig instanceConfig = instanceConfigMarshaller.fromMapAttributes(attributes);
        Injector instanceInjector = createInjector(instanceConfig);
        publisher.publishInstance(instanceConfig, instanceInjector.getInstance(RestSTS.class), false);
    }

    @Override
    protected JsonValue readSTSInstance(String realm, String resourceId, Context context)
            throws STSPublishException, InternalServerErrorException {
        String internalId = getInternalId(realm, resourceId);
        RestSTSInstanceConfig instanceConfig = publisher.getPublishedInstance(internalId, realm);
        return configToJsonValue(realm, resourceId, context, instanceConfig);
    }

    @Override
    protected void updateSTSInstance(String realm, String resourceId, Map<String, Set<String>> attributes)
            throws STSPublishException, InternalServerErrorException {
        String internalId = getInternalId(realm, resourceId);
        RestSTSInstanceConfig newInstanceConfig = instanceConfigMarshaller.fromMapAttributes(attributes);
        Injector instanceInjector = createInjector(newInstanceConfig);
        publisher.updateInstanceInSMS(internalId, realm, newInstanceConfig, instanceInjector.getInstance(RestSTS.class));
    }

    @Override
    protected void deleteSTSInstance(String realm, String resourceId) throws STSPublishException {
        String internalId = getInternalId(realm, resourceId);
        publisher.removeInstance(internalId, realm, false);
    }

    @Override
    protected Map<String, Set<String>> getAttributesForUpdate(String realm, String resourceId,
            Map<String, Set<String>> requestAttributes) throws STSPublishException, BadRequestException {
        String internalId = getInternalId(realm, resourceId);
        RestSTSInstanceConfig instanceConfig = publisher.getPublishedInstance(internalId, realm);
        Map<String, Set<String>> attributes = instanceConfig.marshalToAttributeMap();
        mergeAttributes(attributes, requestAttributes);
        return attributes;
    }

    @Override
    protected List<ResourceResponse> getResourcesInRealm(String realm, Context context)
            throws STSPublishException, InternalServerErrorException {
        List<ResourceResponse> results = new ArrayList<>();
        List<RestSTSInstanceConfig> publishedInstances = publisher.getPublishedInstances();
        for (RestSTSInstanceConfig config : publishedInstances) {
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
        List<RestSTSInstanceConfig> publishedInstances = publisher.getPublishedInstances();
        for (RestSTSInstanceConfig config : publishedInstances) {
            if (realm.equals(config.getDeploymentConfig().getRealm())
                    && resourceId.equals(config.getDeploymentConfig().getUriElement())) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void validateStsTypeSpecificConfiguration(Map<String, Set<String>> attributes) throws BadRequestException {
        /*
         * Need to check if selected transforms include both the validate_interim_session and !invalidate_interim_session
         * flavors. If the token transformation set includes two entries for a specific input token type, then this is the
         * case, and the configuration must be rejected.
         */
        final Set<String> supportedTokenTransforms = attributes.get(SharedSTSConstants.SUPPORTED_TOKEN_TRANSFORMS);
        if (duplicateTransformsSpecified(supportedTokenTransforms)) {
            throw new BadRequestException("Only a single transform of a specified input token type can be selected");
        }

        Set<TokenTransformConfig> customTokenTransforms = new HashSet<>();
        final Set<String> customTokenTransformsAttrs = attributes.get(SharedSTSConstants.CUSTOM_TOKEN_TRANSFORMS);
        if (customTokenTransformsAttrs != null) {
            for (String attr : customTokenTransformsAttrs) {
                try {
                    customTokenTransforms.add(TokenTransformConfig.fromSMSString(attr));
                } catch (IllegalArgumentException e) {
                    throw new BadRequestException(
                            "Custom Token Transforms must be of format: input_token_type|output_token_type|true_or_false");
                }
            }
        }
        Set<CustomTokenOperation> customTokenValidators = new HashSet<>();
        final Set<String> customTokenValidatorsAttrs = attributes.get(SharedSTSConstants.CUSTOM_TOKEN_VALIDATORS);
        if (customTokenValidatorsAttrs != null) {
            for (String attr : customTokenValidatorsAttrs) {
                try {
                    CustomTokenOperation op = CustomTokenOperation.fromSMSString(attr);
                    Class.forName(op.getCustomOperationClassName())
                            .asSubclass(RestTokenTransformValidator.class)
                            .getDeclaredConstructor()
                            .newInstance();
                    customTokenValidators.add(op);
                } catch (IllegalArgumentException e) {
                    throw new BadRequestException(
                            "Custom Token Validators must be of format: custom_token_name|impl_class_name");
                } catch (ClassNotFoundException e) {
                    throw new BadRequestException("Custom Token Validators setting contains an invalid class name");
                } catch (InstantiationException | IllegalAccessException | InvocationTargetException
                        | NoSuchMethodException | SecurityException e) {
                    throw new BadRequestException("Unable to create an instance of Custom Token Validator class");
                }
            }
        }
        Set<CustomTokenOperation> customTokenProviders = new HashSet<>();
        final Set<String> customTokenProvidersAttrs = attributes.get(SharedSTSConstants.CUSTOM_TOKEN_PROVIDERS);
        if (customTokenProvidersAttrs != null) {
            for (String attr : customTokenProvidersAttrs) {
                try {
                    CustomTokenOperation op = CustomTokenOperation.fromSMSString(attr);
                    Class.forName(op.getCustomOperationClassName())
                            .asSubclass(RestTokenProvider.class)
                            .getDeclaredConstructor()
                            .newInstance();
                    customTokenProviders.add(op);
                } catch (IllegalArgumentException e) {
                    throw new BadRequestException(
                            "Custom Token Providers must be of format: custom_token_name|impl_class_name");
                } catch (ClassNotFoundException e) {
                    throw new BadRequestException("Custom Token Providers setting contains an invalid class name");
                } catch (InstantiationException | IllegalAccessException | InvocationTargetException
                        | NoSuchMethodException | SecurityException e) {
                    throw new BadRequestException("Unable to create an instance of Custom Token Provider class");
                }
            }
        }
        for (TokenTransformConfig tokenTransformConfig : customTokenTransforms) {
            boolean foundValidator = false;
            boolean foundProvider = false;
            for (CustomTokenOperation customTokenOperation : customTokenValidators) {
                if (customTokenOperation.getCustomTokenName().equals(tokenTransformConfig.getInputTokenType().getId())) {
                    foundValidator = true;
                    break;
                }
            }
            for (CustomTokenOperation customTokenOperation : customTokenProviders) {
                if (customTokenOperation.getCustomTokenName().equals(tokenTransformConfig.getOutputTokenType().getId())) {
                    foundProvider = true;
                    break;
                }
            }
            /*
             * custom token transforms can reference non-custom tokens - only if neither a custom token validator or
             * custom token provider is referenced, is the configuration incorrect.
             */
            if (!foundProvider || !foundValidator) {
                throw new BadRequestException(
                        "No Custom Token Provider or Custom Token Validator found to realize the Custom Token Transform");
            }
        }

        String offloadedTwoWayTLSHeaderKey = CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OFFLOADED_TWO_WAY_TLS_HEADER_KEY);
        Set<String> tlsOffloadEngineHostIpAddrs = attributes.get(SharedSTSConstants.TLS_OFFLOAD_ENGINE_HOSTS);
        if (((offloadedTwoWayTLSHeaderKey != null) && (tlsOffloadEngineHostIpAddrs == null || tlsOffloadEngineHostIpAddrs.isEmpty())) ||
                ((offloadedTwoWayTLSHeaderKey == null) && (tlsOffloadEngineHostIpAddrs != null && !tlsOffloadEngineHostIpAddrs.isEmpty()))) {
            throw new BadRequestException("Client Certificate Header Key and Trusted Remote Hosts must be set together");
        }
    }

    @Override
    protected Set<String> getSupportedTokenTypes(Map<String, Set<String>> attributes) {
        Set<String> types = new HashSet<String>();
        final Set<String> supportedTokenTransforms = attributes.get(SharedSTSConstants.SUPPORTED_TOKEN_TRANSFORMS);
        for (String transform : supportedTokenTransforms) {
            String[] breakdown = transform.split(REGEX_PIPE);
            types.add(breakdown[1]);
        }
        return types;
    }

    @Override
    protected void addStsTypeSpecificInternalConfiguration(Map<String, Set<String>> attributes) {
        // No specific configuration
    }

    @Override
    protected String getTokenTypeAttributeTitle() {
        return "Supported Token Transforms";
    }

    private JsonValue configToJsonValue(String realm, String resourceId, Context context,
            RestSTSInstanceConfig instanceConfig)
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

    private Injector createInjector(RestSTSInstanceConfig instanceConfig) throws InternalServerErrorException {
        try {
            return Guice.createInjector(new RestSTSInstanceModule(instanceConfig));
        } catch (Exception e) {
            throw new InternalServerErrorException();
        }
    }

    /**
     * The set of possible token transformation definition selections, as defined in the supported-token-transforms property
     * in restSTS.xml, is as follow:
     *      USERNAME|SAML2|true
     *      USERNAME|SAML2|false
     *      OPENIDCONNECT|SAML2|true
     *      OPENIDCONNECT|SAML2|false
     *      OPENAM|SAML2|true
     *      OPENAM|SAML2|false
     *      X509|SAML2|true
     *      X509|SAML2|false
     *      USERNAME|OPENIDCONNECT|true
     *      USERNAME|OPENIDCONNECT|false
     *      OPENIDCONNECT|OPENIDCONNECT|true
     *      OPENIDCONNECT|OPENIDCONNECT|false
     *      OPENAM|OPENIDCONNECT|true
     *      OPENAM|OPENIDCONNECT|false
     *      X509|OPENIDCONNECT|true
     *      X509|OPENIDCONNECT|false
     * This method will return true if the supportedTokenTransforms method specified by the user contains more than a single
     * entry for a given input token type per given output token type.
     * @param supportedTokenTransforms The set of supported token transformations specified by the user
     * @return true if duplicate transformations are specified - i.e. the user cannot specify token transformations with
     * USERNAME input which specify that interim OpenAM sessions should be, and should not be, invalidated.
     */
    private boolean duplicateTransformsSpecified(Set<String> supportedTokenTransforms) {
        Set<String> inputOutputComboSet = new HashSet<>(supportedTokenTransforms.size());
        for (String transform : supportedTokenTransforms) {
            String[] breakdown = transform.split(REGEX_PIPE);
            String entry = breakdown[0] + breakdown[1];
            if (inputOutputComboSet.contains(entry)) {
                return true;
            } else {
                inputOutputComboSet.add(entry);
            }
        }
        return false;
    }
}
