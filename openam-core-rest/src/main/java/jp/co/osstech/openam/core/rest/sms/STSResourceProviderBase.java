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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.OBJECT_TYPE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.PROPERTIES;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.TYPE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.addAttributeSchema;
import static org.forgerock.openam.utils.CollectionUtils.asSet;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ConflictException;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.json.resource.annotations.Create;
import org.forgerock.json.resource.annotations.Delete;
import org.forgerock.json.resource.annotations.Query;
import org.forgerock.json.resource.annotations.Read;
import org.forgerock.json.resource.annotations.Update;
import org.forgerock.openam.core.rest.sms.SmsJsonConverter;
import org.forgerock.openam.core.rest.sms.SmsResourceProvider;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.openam.shared.sts.SharedSTSConstants;
import org.forgerock.openam.sts.STSPublishException;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.query.QueryFilter;

import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;

/**
 * REST resource base for REST STS & SOAP STS Management.
 */
public abstract class STSResourceProviderBase extends SmsResourceProvider {

    public static final String REGEX_PIPE = "\\|";

    private static final String TOKEN_TYPE_SAML = "SAML2";
    private static final String TOKEN_TYPE_OIDC = "OPENIDCONNECT";

    private static final String DEPLOYMENT_AUTH_TARGET_MAPPINGS = "deployment-auth-target-mappings";
    private static final Pattern AUTH_TARGET_MAPPINGS_FORMAT =
            Pattern.compile("^(SAML2|USERNAME|OPENAM|OPENIDCONNECT|X509)\\|(module|service)\\|[^\\|]+(\\|[^,\\|]+=[^,\\|]+(,[^,\\|]+=[^,\\|]+)*)?$");

    public STSResourceProviderBase(ServiceSchema schema, SchemaType type, List<ServiceSchema> subSchemaPath,
            String uriPath, boolean serviceHasInstanceName, SmsJsonConverter converter, Debug debug,
            AMResourceBundleCache resourceBundleCache, Locale defaultLocale) {
        super(schema, type, subSchemaPath, uriPath, serviceHasInstanceName, converter, debug, resourceBundleCache,
                defaultLocale);
    }

    @Override
    protected JsonValue createSchema(Context context) {
        JsonValue result = json(object(field(TYPE, OBJECT_TYPE)));
        addAttributeSchema(result, "/" + PROPERTIES + "/", schema, getLocale(context),
                realmFor(context), new STSAttributeSchemaFilter());
        return result;
    }

    @Create
    public Promise<ResourceResponse, ResourceException> createInstance(final Context context, CreateRequest request) {
        JsonValue content = request.getContent();
        final String realm = realmFor(context);

        try {
            final String resourceId = content.get(ResourceResponse.FIELD_CONTENT_ID).asString();
            if (StringUtils.isEmpty(resourceId)) {
                return new BadRequestException("Invalid name").asPromise();
            }

            if (exists(realm, resourceId)) {
                return new ConflictException("Resource already exists").asPromise();
            }

            Map<String, Set<String>> attributes = converter.fromJson(realm, content);
            attributes.put(SharedSTSConstants.DEPLOYMENT_URL_ELEMENT, asSet(resourceId));
            addInternalConfiguration(attributes, realm);

            // Check for required attributes
            AttributeSchemaFilter filter = new STSAttributeSchemaFilter();
            for (AttributeSchema attrSchema : schema.getAttributeSchemas()) {
                if (filter.isTarget(attrSchema) && filter.isRequired(attrSchema)) {
                    Set<String> values = attributes.get(attrSchema.getName());
                    if (isEmptyAttribute(values)) {
                        throw new BadRequestException(attrSchema.getName() + " is not specified");
                    }
                }
            }
            validateConfiguration(attributes);

            createSTSInstance(attributes);

            JsonValue result = readSTSInstance(realm, resourceId, context);
            return newResultPromise(newResourceResponse(resourceId, String.valueOf(result.hashCode()), result));
        } catch (STSPublishException e) {
            debug.warning("STSResourceProviderBase.createInstance() :: Cannot CREATE resource", e);
            return e.asPromise();
        } catch (InternalServerErrorException e) {
            debug.error("STSResourceProviderBase.createInstance() :: Cannot CREATE resource", e);
            return e.asPromise();
        } catch (BadRequestException e) {
            debug.warning("STSResourceProviderBase.createInstance() :: Cannot CREATE resource", e);
            return e.asPromise();
        }
    }

    @Read
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, String resourceId) {
        final String realm = realmFor(context);
        try {
            if (!exists(realm, resourceId)) {
                return new NotFoundException().asPromise();
            }

            JsonValue result = readSTSInstance(realm, resourceId, context);
            return newResultPromise(newResourceResponse(resourceId, String.valueOf(result.hashCode()), result));
        } catch (STSPublishException e) {
            debug.warning("STSResourceProviderBase.readInstance() :: Cannot READ resource", e);
            return e.asPromise();
        } catch (InternalServerErrorException e) {
            debug.error("STSResourceProviderBase.readInstance() :: Cannot READ resource", e);
            return e.asPromise();
        }
    }

    @Update
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, String resourceId,
            UpdateRequest request) {
        JsonValue content = request.getContent();
        final String realm = realmFor(context);

        try {
            if (!exists(realm, resourceId)) {
                return new NotFoundException().asPromise();
            }

            Map<String, Set<String>> requestAttributes = converter.fromJson(realm, content);
            Map<String, Set<String>> attributes = getAttributesForUpdate(realm, resourceId, requestAttributes);
            addInternalConfiguration(attributes, realm); // For Update

            validateConfiguration(attributes);

            updateSTSInstance(realm, resourceId, attributes);

            JsonValue result = readSTSInstance(realm, resourceId, context);
            return newResultPromise(newResourceResponse(resourceId, String.valueOf(result.hashCode()), result));
        } catch (STSPublishException e) {
            debug.warning("STSResourceProviderBase.updateInstance() :: Cannot UPDATE resource", e);
            return e.asPromise();
        } catch (InternalServerErrorException e) {
            debug.error("STSResourceProviderBase.updateInstance() :: Cannot UPDATE resource", e);
            return e.asPromise();
        } catch (BadRequestException e) {
            debug.warning("STSResourceProviderBase.updateInstance() :: Cannot UPDATE resource", e);
            return e.asPromise();
        }
    }

    @Delete
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context, final String resourceId) {
        final String realm = realmFor(context);

        try {
            if (!exists(realm, resourceId)) {
                return new NotFoundException().asPromise();
            }

            deleteSTSInstance(realm, resourceId);

            return newResultPromise(newResourceResponse(resourceId, "0", json(object(field("success", true)))));
        } catch (STSPublishException e) {
            debug.warning("STSResourceProviderBase.deleteInstance() :: Cannot DELETE resource", e);
            return e.asPromise();
        }
    }

    @Query
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {
        final String realm = realmFor(context);

        try {
            QueryFilter<JsonPointer> queryFilter = request.getQueryFilter();
            if (queryFilter != null && !"true".equals(queryFilter.toString())) {
                return new NotSupportedException("Query filter not supported").asPromise();
            }
            String pattern = request.getQueryId();
            if (pattern != null && !pattern.isEmpty()) {
                return new NotSupportedException("Query Id not supported").asPromise();
            }

            List<ResourceResponse> results = getResourcesInRealm(realm, context);

            return QueryResponsePresentation.perform(handler, request, results);
        } catch (STSPublishException e) {
            debug.warning("STSResourceProviderBase.queryCollection() :: Cannot QUERY resource", e);
            return e.asPromise();
        } catch (InternalServerErrorException e) {
            debug.error("STSResourceProviderBase.queryCollection() :: Cannot QUERY resource", e);
            return e.asPromise();
        }
    }

    /**
     * Returns the internal ID for STS.
     *
     * @param realm the realm
     * @param resourceId the resource id
     * @return the internal ID
     */
    protected String getInternalId(String realm, String resourceId) {
        return "/".equals(realm) ? resourceId : realm.substring(1) + "/" + resourceId;
    }

    /**
     * Merges current attributes and requested attributes.
     *
     * @param attributes current STS attributes
     * @param requestAttributes requested attributes
     * @throws BadRequestException
     */
    protected void mergeAttributes(Map<String, Set<String>> attributes, Map<String, Set<String>> requestAttributes)
            throws BadRequestException {
        AttributeSchemaFilter filter = new STSAttributeSchemaFilter();
        for (AttributeSchema attribute : schema.getAttributeSchemas()) {
            if (filter.isTarget(attribute)) {
                if (requestAttributes.containsKey(attribute.getName())) {
                    Set<String> values = requestAttributes.get(attribute.getName());
                    if (isEmptyAttribute(values)) {
                        if (filter.isRequired(attribute)) {
                            throw new BadRequestException(attribute.getName() + " is not specified");
                        } else {
                            // If the key exists and the value is empty, delete the attribute.
                            attributes.put(attribute.getName(), Collections.<String>emptySet());
                        }
                    } else {
                        attributes.put(attribute.getName(), values);
                    }
                } else {
                    // Check for required attributes
                    if (filter.isRequired(attribute)) {
                        throw new BadRequestException(attribute.getName() + " is not specified");
                    }
                }
            }
        }
    }

    /**
     * Creates STS instance.
     *
     * @param attributes the STS attributes
     * @throws STSPublishException
     * @throws InternalServerErrorException
     */
    protected abstract void createSTSInstance(Map<String, Set<String>> attributes)
            throws STSPublishException, InternalServerErrorException;

    /**
     * Reads STS instance.
     *
     * @param realm the realm
     * @param resourceId the resource id
     * @param context the request context
     * @return JSON representation of STS instance
     * @throws STSPublishException
     * @throws InternalServerErrorException
     */
    protected abstract JsonValue readSTSInstance(String realm, String resourceId, Context context)
            throws STSPublishException, InternalServerErrorException;

    /**
     * Reads STS instance.
     *
     * @param realm the realm
     * @param resourceId the resource id
     * @param attributes the STS attributes
     * @throws STSPublishException
     * @throws InternalServerErrorException
     */
    protected abstract void updateSTSInstance(String realm, String resourceId, Map<String, Set<String>> attributes)
            throws STSPublishException, InternalServerErrorException;

    /**
     * Deletes STS instance.
     *
     * @param realm the realm
     * @param resourceId the resource id
     * @throws STSPublishException
     */
    protected abstract void deleteSTSInstance(String realm, String resourceId)
            throws STSPublishException;

    /**
     * Returns STS attributes for update.
     *
     * @param realm the realm
     * @param resourceId the resource id
     * @param requestAttributes requested attributes
     * @return STS attributes for update
     * @throws STSPublishException
     * @throws BadRequestException
     */
    protected abstract Map<String, Set<String>> getAttributesForUpdate(String realm, String resourceId,
            Map<String, Set<String>> requestAttributes) throws STSPublishException, BadRequestException;

    /**
     * Returns STS instance resources in the realm.
     *
     * @param realm the realm
     * @param context the request context
     * @return STS instance resources in the realm
     * @throws STSPublishException
     * @throws InternalServerErrorException
     */
    protected abstract List<ResourceResponse> getResourcesInRealm(String realm, Context context)
            throws STSPublishException, InternalServerErrorException;

    /**
     * Returns whether the STS instance with specified id exists.
     *
     * @param realm the realm
     * @param resourceId the resource id
     * @return true if the STS instance exists
     * @throws STSPublishException
     */
    protected abstract boolean exists(String realm, String resourceId) throws STSPublishException;

    /**
     * Validates STS type specific configuration.
     *
     * @param attributes the STS attributes
     * @throws BadRequestException
     */
    protected abstract void validateStsTypeSpecificConfiguration(Map<String, Set<String>> attributes) throws BadRequestException;

    /**
     * Adds STS type specific internal configuration.
     *
     * @param attributes the STS attributes
     */
    protected abstract void addStsTypeSpecificInternalConfiguration(Map<String, Set<String>> attributes);

    /**
     * Returns Set of supported token types.
     *
     * @param attributes the STS attributes
     * @return Set of supported token types
     */
    protected abstract Set<String> getSupportedTokenTypes(Map<String, Set<String>> attributes);

    /**
     * Returns the title of token type attribute.
     *
     * @return the title of token type attribute
     */
    protected abstract String getTokenTypeAttributeTitle();

    private void validateConfiguration(Map<String, Set<String>> attributes) throws BadRequestException {
        String urlElement = attributes.get(SharedSTSConstants.DEPLOYMENT_URL_ELEMENT).iterator().next();
        if (urlElement.contains(SharedSTSConstants.FORWARD_SLASH)) {
            throw new BadRequestException("Deployment Url element can neither start, end, nor contain, the '/' character");
        }

        Set<String> authTargetMappings = attributes.get(DEPLOYMENT_AUTH_TARGET_MAPPINGS);
        if (authTargetMappings != null) {
            for (String config : authTargetMappings) {
                if (!AUTH_TARGET_MAPPINGS_FORMAT.matcher(config).matches()) {
                    throw new BadRequestException("Invalid field value syntax: 'Authentication Target Mappings'");
                }
            }
        }

        validateStsTypeSpecificConfiguration(attributes);
        Set<String> tokenTypes = getSupportedTokenTypes(attributes);

        if (tokenTypes.contains(TOKEN_TYPE_SAML)) {
            validateSAML2Configuration(attributes);
        } else {
            if (!StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.ISSUER_NAME))) {
                throw new BadRequestException(getTokenTypeAttributeTitle() + " does not contain "
                        + TOKEN_TYPE_SAML + ", so " + SharedSTSConstants.ISSUER_NAME + " must not be specified.");
            }
        }

        if (tokenTypes.contains(TOKEN_TYPE_OIDC)) {
            validateOIDCConfiguration(attributes);
        } else {
            if (!StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_ISSUER))) {
                throw new BadRequestException(getTokenTypeAttributeTitle() + " does not contain "
                        + TOKEN_TYPE_OIDC + ", so " + SharedSTSConstants.OIDC_ISSUER + " must not be specified.");
            }
        }
    }

    private void addInternalConfiguration(Map<String, Set<String>> attributes, String realm) {
        attributes.put(SharedSTSConstants.DEPLOYMENT_REALM, CollectionUtils.asSet(realm));
        if (!CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.ISSUER_NAME))) {
            String encryptionAlgorithm = CollectionHelper.getMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPTION_ALGORITHM);
            if (encryptionAlgorithm == null) {
                encryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
                attributes.put(SharedSTSConstants.SAML2_ENCRYPTION_ALGORITHM,
                        CollectionUtils.asSet(encryptionAlgorithm));
            }
            String encryptionAlgorithmStrength;
            switch (encryptionAlgorithm) {
                case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
                    encryptionAlgorithmStrength = "128";
                    break;
                case "http://www.w3.org/2001/04/xmlenc#aes192-cbc":
                    encryptionAlgorithmStrength = "192";
                    break;
                case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
                    encryptionAlgorithmStrength = "256";
                    break;
                default:
                    encryptionAlgorithmStrength = "128";
            }
            attributes.put(SharedSTSConstants.SAML2_ENCRYPTION_ALGORITHM_STRENGTH,
                    CollectionUtils.asSet(encryptionAlgorithmStrength));
        }
        addStsTypeSpecificInternalConfiguration(attributes);
    }

    private void validateSAML2Configuration(Map<String, Set<String>> attributes) throws BadRequestException {
        if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.ISSUER_NAME))) {
            throw new BadRequestException("The SAML2 issuer Id must be specified");
        }

        if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.SAML2_SP_ENTITY_ID))) {
            throw new BadRequestException("Service Provider Entity Id must be specified");
        }

        if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.SAML2_TOKEN_LIFETIME))) {
            throw new BadRequestException("SAML2 token lifetime must be specified");
        }

        if (CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_SIGN_ASSERTION, false)
                || CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_ASSERTION, false)
                || CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_ATTRIBUTES, false)
                || CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_NAME_ID, false)) {

            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.SAML2_KEYSTORE_FILE_NAME))) {
                throw new BadRequestException("Keystore filename must be specified if assertion signing or encryption is configured");
            }
            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.SAML2_KEYSTORE_PASSWORD))) {
                throw new BadRequestException("Keystore password must be specified if assertion signing or encryption is configured");
            }
        }
        if (CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_SIGN_ASSERTION, false)) {
            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.SAML2_SIGNATURE_KEY_ALIAS))) {
                throw new BadRequestException("Keystore signature key alias must be specified if assertion signing is configured");
            }
            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.SAML2_SIGNATURE_KEY_PASSWORD))) {
                throw new BadRequestException("Keystore signature key password must be specified");
            }
        }
        if (CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_ASSERTION, false)
                || CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_ATTRIBUTES, false)
                || CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_NAME_ID, false)) {

            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPTION_KEY_ALIAS))) {
                throw new BadRequestException("Keystore encryption key alias must be specified if assertion encryption is configured");
            }
        }
        if (CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_ASSERTION, false)
                && (CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_ATTRIBUTES, false)
                    || CollectionHelper.getBooleanMapAttr(attributes, SharedSTSConstants.SAML2_ENCRYPT_NAME_ID, false))) {
            throw new BadRequestException("If Encrypt Assertion is selected, then neither Encrypt NameID nor Encrypt Attributes can be selected."
                    + " Attributes and/or NameIDs can be encrypted, but not in conjunction with assertion encryption.");
        }

        if (!CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.SAML2_ATTRIBUTE_MAP))) {
            if (!attributeMappingCorrectFormat(attributes.get(SharedSTSConstants.SAML2_ATTRIBUTE_MAP))) {
                throw new BadRequestException("The SAML2 attribute map must be of format assertion_attr_name=ldap_attr_name");
            }
        }
    }

    private void validateOIDCConfiguration(Map<String, Set<String>> attributes) throws BadRequestException {
        if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_ISSUER))) {
            throw new BadRequestException("The id of the OpenIdConnect Token Provider must be specified");
        }

        if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_TOKEN_LIFETIME))) {
            throw new BadRequestException("OpenIdConnect token lifetime must be specified");
        }

        String sigAlg = CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_SIGNATURE_ALGORITHM);
        if (StringUtils.isEmpty(sigAlg)) {
            throw new BadRequestException("A signature algorithm for OpenIdConnect tokens must be specified");
        }

        if (sigAlg.startsWith("RS")) {
            // RSA Signature
            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_KEYSTORE_LOCATION))) {
                throw new BadRequestException("The KeyStore location must be specified for RSA-signed tokens");
            }
            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_KEYSTORE_PASSWORD))) {
                throw new BadRequestException("The KeyStore password must be specified for RSA-signed tokens");
            }
            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_SIGNATURE_KEY_ALIAS))) {
                throw new BadRequestException("The signature key alias must be specified for RSA-signed tokens");
            }
            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_SIGNATURE_KEY_PASSWORD))) {
                throw new BadRequestException("The signature key password must be specified for RSA-signed tokens");
            }
        } else {
            // HMAC Signature
            if (StringUtils.isEmpty(CollectionHelper.getMapAttr(attributes, SharedSTSConstants.OIDC_CLIENT_SECRET))) {
                throw new BadRequestException("The client secret must be specified for HMAC-signed tokens");
            }
        }

        if (CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.OIDC_AUDIENCE))) {
            throw new BadRequestException("An audience for issued OpenIdConnect tokens must be specified");
        }

        if (!CollectionUtils.isEmpty(attributes.get(SharedSTSConstants.OIDC_CLAIM_MAP))) {
            if (!attributeMappingCorrectFormat(attributes.get(SharedSTSConstants.OIDC_CLAIM_MAP))) {
                throw new BadRequestException("The OpenIdConnect claim map must be of format claim-name=attribute-name");
            }
        }
    }

    private boolean attributeMappingCorrectFormat(Set<String> attributeMapping) {
        for (String mapping : attributeMapping) {
            if (mapping.split("=").length != 2) {
                return false;
            }
        }
        return true;
    }

    private boolean isEmptyAttribute(Set<String> attrSet) {
        if (CollectionUtils.isEmpty(attrSet)) {
            return true;
        }
        for (String attr : attrSet) {
            if (attr != null && !attr.isEmpty()) {
                return false;
            }
        }
        return true;
    }
}
