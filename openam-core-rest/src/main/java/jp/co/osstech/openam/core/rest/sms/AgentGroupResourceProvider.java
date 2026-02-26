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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

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
import org.forgerock.json.resource.annotations.RequestHandler;
import org.forgerock.json.resource.annotations.Update;
import org.forgerock.openam.core.rest.sms.SmsJsonConverter;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.Context;
import org.forgerock.util.Function;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.query.QueryFilter;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.config.AMConfigurationException;
import com.sun.identity.common.configuration.AgentConfiguration;
import com.sun.identity.common.configuration.ConfigurationException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdConstants;
import com.sun.identity.idm.IdRepoDuplicateObjectException;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchOpModifier;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import com.sun.identity.sm.ServiceSchema;

/**
 * REST resource for Agent Group Management.
 */
@RequestHandler
public class AgentGroupResourceProvider extends AgentResourceProviderBase {

    @Inject
    public AgentGroupResourceProvider(@Assisted SmsJsonConverter converter, @Assisted ServiceSchema schema,
            @Assisted SchemaType type, @Assisted List<ServiceSchema> subSchemaPath, @Assisted String uriPath,
            @Assisted boolean serviceHasInstanceName, @Named("frRest") Debug debug,
            @Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache,
            @Named("DefaultLocale") Locale defaultLocale) {
        super(schema, type, subSchemaPath, uriPath, serviceHasInstanceName, converter, debug, resourceBundleCache,
                defaultLocale);
    }

    protected JsonValue createSchema(Context context) {
        JsonValue result = json(object(field(TYPE, OBJECT_TYPE)));
        if (schema.getServiceType().equals(SchemaType.ORGANIZATION)) {
            addAttributeSchema(result, "/" + PROPERTIES + "/", schema, getLocale(context),
                    realmFor(context), new AgentGroupAttributeSchemaFilter());
        }
        return result;
    }

    protected JsonValue createTemplate() {
        Map<String, Set<String>> defaults = schema.getAttributeDefaults();
        defaults.remove(AgentConfiguration.ATTR_NAME_PWD);
        defaults.remove(AgentConfiguration.ATTR_CONFIG_REPO);
        defaults.remove(AgentConfiguration.ATTR_NAME_GROUP);

        // Workaround : The default value of AM_SERVER_PORT does not match syntax
        String agentType = schema.getName();
        String serverPort = null;
        if (AgentConfiguration.AGENT_TYPE_J2EE.equals(agentType)) {
            serverPort = defaults.get(AM_SERVER_PORT).iterator().next();
            defaults.put(AM_SERVER_PORT, asSet("0"));
        }

        JsonValue result = converter.toJson(null, defaults, false);

        // Workaround
        if (AgentConfiguration.AGENT_TYPE_J2EE.equals(agentType)) {
            result.putPermissive(new JsonPointer("/fam/" + AM_SERVER_PORT),
                    serverPort);
        }
        return result;
    }

    @Create
    public Promise<ResourceResponse, ResourceException> createInstance(final Context context, CreateRequest request) {
        JsonValue content = request.getContent();
        final String realm = realmFor(context);
        try {
            final SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            Map<String, Set<String>> requestAttrs = converter.fromJson(realm, content, false,
                    null, null, null, new AgentGroupAttributeSchemaFilter());
            ServiceConfigManager scm = getServiceConfigManager(context);

            final String groupName = content.get(ResourceResponse.FIELD_CONTENT_ID).asString();
            if (StringUtils.isEmpty(groupName)) {
                return new BadRequestException("Invalid name").asPromise();
            }

            createAgentGroup(admin, realm, groupName, requestAttrs);

            final ServiceConfig parentConfig = scm.getOrganizationConfig(realm,
                    AgentConfiguration.ATTR_NAME_GROUP);

            return awaitCreation(context, groupName)
                    .then(new Function<Void, ResourceResponse, ResourceException>() {
                        @Override
                        public ResourceResponse apply(Void aVoid) {
                            JsonValue result = null;
                            try {
                                result = readAgentGroup(admin, realm, groupName, parentConfig, context);
                            } catch (NotFoundException e) {
                                debug.warning("Error creating JsonValue", e);
                            } catch (InternalServerErrorException e) {
                                debug.warning("Error creating JsonValue", e);
                            }
                            return newResourceResponse(groupName, String.valueOf(result.hashCode()), result);
                        }
                    });
        } catch (SSOException e) {
            debug.error("AgentGroupResourceProvider.createInstance() :: Cannot CREATE resource", e);
            return new InternalServerErrorException("Unable to create agentgroup config").asPromise();
        } catch (IdRepoDuplicateObjectException e) {
            debug.error("AgentGroupResourceProvider.createInstance() :: Cannot CREATE resource", e);
            return new ConflictException("Resource already exists").asPromise();
        } catch (IdRepoException e) {
            debug.error("AgentGroupResourceProvider.createInstance() :: Cannot CREATE resource", e);
            return new InternalServerErrorException("Unable to create agentgroup config").asPromise();
        } catch (SMSException e) {
            debug.error("AgentGroupResourceProvider.createInstance() :: Cannot CREATE resource", e);
            return new InternalServerErrorException("Unable to create agentgroup config").asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Read
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, String resourceId) {
        final String realm = realmFor(context);
        try {
            final SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            ServiceConfigManager scm = getServiceConfigManager(context);
            ServiceConfig parentConfig;
            try {
                parentConfig = scm.getOrganizationConfig(realm, AgentConfiguration.ATTR_NAME_GROUP);
            } catch (SMSException e) {
                throw new NotFoundException();
            }
            checkedInstanceSubConfig(context, resourceId, parentConfig);

            JsonValue result = readAgentGroup(admin, realm, resourceId, parentConfig, context);
            return newResultPromise(newResourceResponse(resourceId, String.valueOf(result.hashCode()), result));
        } catch (SMSException e) {
            debug.error("AgentGroupResourceProvider.readInstance() :: Cannot READ resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to read agentgroup config").asPromise();
        } catch (SSOException e) {
            debug.error("AgentGroupResourceProvider.readInstance() :: Cannot READ resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to read agentgroup config").asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Update
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, String resourceId,
            UpdateRequest request) {
        JsonValue content = request.getContent();
        String realm = realmFor(context);
        try {
            final SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            Map<String, Set<String>> requestAttrs = converter.fromJson(realm, content, false,
                    null, null, null, new AgentGroupAttributeSchemaFilter());
            ServiceConfigManager scm = getServiceConfigManager(context);
            ServiceConfig parentConfig;
            try {
                parentConfig = scm.getOrganizationConfig(realm, AgentConfiguration.ATTR_NAME_GROUP);
            } catch (SMSException e) {
                throw new NotFoundException();
            }
            checkedInstanceSubConfig(context, resourceId, parentConfig);

            updateAgentGroup(admin, realm, resourceId, requestAttrs);

            JsonValue result = readAgentGroup(admin, realm, resourceId, parentConfig, context);
            return newResultPromise(newResourceResponse(resourceId, String.valueOf(result.hashCode()), result));
        } catch (SMSException e) {
            debug.error("AgentGroupResourceProvider.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to update agentgroup config").asPromise();
        } catch (SSOException e) {
            debug.error("AgentGroupResourceProvider.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to update agentgroup config").asPromise();
        } catch (IdRepoException e) {
            debug.error("AgentGroupResourceProvider.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to update agentgroup config").asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Delete
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context, final String resourceId) {
        try {
            String realm = realmFor(context);
            final SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            ServiceConfigManager scm = getServiceConfigManager(context);
            ServiceConfig parentConfig;
            try {
                parentConfig = scm.getOrganizationConfig(realm, AgentConfiguration.ATTR_NAME_GROUP);
            } catch (SMSException e) {
                throw new NotFoundException();
            }
            checkedInstanceSubConfig(context, resourceId, parentConfig);

            AMIdentity amid = new AMIdentity(admin, resourceId,
                    IdType.AGENTGROUP, realm, null);
            AgentConfiguration.deleteAgentGroups(admin, realm, asSet(amid));

            return awaitDeletion(context, resourceId)
                    .then(new Function<Void, ResourceResponse, ResourceException>() {
                        @Override
                        public ResourceResponse apply(Void aVoid) {
                            return newResourceResponse(resourceId, "0", json(object(field("success", true))));
                        }
                    });
        } catch (SMSException e) {
            debug.error("AgentGroupResourceProvider.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to delete agentgroup config").asPromise();
        } catch (SSOException e) {
            debug.error("AgentGroupResourceProvider.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to delete agentgroup config").asPromise();
        } catch (IdRepoException e) {
            debug.error("AgentGroupResourceProvider.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to delete agentgroup config").asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Query
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {

        try {
            final SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            QueryFilter<JsonPointer> queryFilter = request.getQueryFilter();
            if (queryFilter != null &&  !"true".equals(queryFilter.toString())) {
                return new NotSupportedException("Query filter not supported").asPromise();
            }

            String groupName = null;
            if (queryFilter != null) {
                groupName = "*";
            } else {
                groupName = request.getQueryId();
                if (groupName == null || groupName.isEmpty()) {
                    groupName = "*";
                }
            }

            String realm = realmFor(context);
            Set<AMIdentity> groups = getAgentGroupIdentities(admin, groupName, realm);

            ServiceConfigManager scm = getServiceConfigManager(context);
            ServiceConfig parentConfig;
            try {
                parentConfig = scm.getOrganizationConfig(realm, AgentConfiguration.ATTR_NAME_GROUP);
            } catch (SMSException e) {
                parentConfig = null;
            }
            List<ResourceResponse> results = new ArrayList<>();
            if (parentConfig != null) {
                for (AMIdentity group : groups) {
                    JsonValue result = agentGroupToJsonValue(admin, realm, group, context);
                    results.add(newResourceResponse(group.getName(), "0", result));
                }
            }

            return QueryResponsePresentation.perform(handler, request, results);
        } catch (SMSException e) {
            debug.error("AgentGroupResourceProvider.queryCollection() :: Cannot QUERY resources", e);
            return new InternalServerErrorException("Unable to query agentgroup config").asPromise();
        } catch (SSOException e) {
            debug.error("AgentGroupResourceProvider.queryCollection() :: Cannot QUERY resources", e);
            return new InternalServerErrorException("Unable to query agentgroup config").asPromise();
        } catch (IdRepoException e) {
            debug.error("AgentGroupResourceProvider.queryCollection() :: Cannot QUERY resources", e);
            return new InternalServerErrorException("Unable to query agentgroup config").asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    private void createAgentGroup(SSOToken adminToken, String realm, String groupName,
            Map<String, Set<String>> requestAttrs)
                    throws SSOException, IdRepoException, BadRequestException {

        Map<String, Set<String>> groupAttrs = new HashMap<String, Set<String>>();

        // Check for required attributes
        AttributeSchemaFilter filter = new AgentGroupAttributeSchemaFilter();
        for (AttributeSchema attribute : schema.getAttributeSchemas()) {
            if (filter.isTarget(attribute) && filter.isRequired(attribute)) {
                Set<String> values = requestAttrs.get(attribute.getName());
                if (isEmptyAttribute(values)) {
                    throw new BadRequestException(attribute.getName() + " is not specified");
                }
            }
        }

        // Merge default values
        Map<String, Set<String>> tmpAttrs = schema.getAttributeDefaults();
        // Workaround : The default value of AM_SERVER_PORT does not match syntax
        String agentType = schema.getName();
        if (AgentConfiguration.AGENT_TYPE_J2EE.equals(agentType)) {
            tmpAttrs.put(AM_SERVER_PORT, asSet(SystemProperties.get("com.iplanet.am.server.port")));
        }
        tmpAttrs.putAll(requestAttrs);

        // Filter out invalid attributes
        for (String attributeName : tmpAttrs.keySet()) {
            final AttributeSchema attributeSchema = schema.getAttributeSchema(attributeName);
            if (filter.isTarget(attributeSchema)) {
                groupAttrs.put(attributeName, tmpAttrs.get(attributeName));
            }
        }

        // Adjust attribute values
        try {
            AgentConfiguration.addAgentRootURLKey(agentType, groupAttrs, false);
        } catch (ConfigurationException e) {
            // Since no validation is performed, no exceptions will be raised
        }

        // Put AgentType
        groupAttrs.put(IdConstants.AGENT_TYPE, asSet(schema.getName()));

        AMIdentityRepository amir = new AMIdentityRepository(realm, adminToken);
        amir.createIdentity(IdType.AGENTGROUP, groupName, groupAttrs);
    }

    private JsonValue readAgentGroup(SSOToken adminToken, String realm, String resourceId,
            ServiceConfig parentConfig, Context context)
                    throws InternalServerErrorException, NotFoundException {

        AMIdentity groupIdentity = new AMIdentity(adminToken, resourceId,
                IdType.AGENTGROUP, realm, null);

        return agentGroupToJsonValue(adminToken, realm, groupIdentity, context);
    }

    private void updateAgentGroup(SSOToken adminToken, String realm, String resourceId,
            Map<String, Set<String>> requestAttrs)
                    throws SSOException, IdRepoException, NotFoundException, BadRequestException {

        AMIdentity amid = new AMIdentity(adminToken, resourceId, IdType.AGENTGROUP, realm, null);
        Map<String, Set<String>> groupAttrs = getAgentAttributes(amid);

        // Filter out invalid attributes
        AttributeSchemaFilter filter = new AgentGroupAttributeSchemaFilter();
        for (AttributeSchema attribute : schema.getAttributeSchemas()) {
            if (filter.isTarget(attribute)) {
                if (requestAttrs.containsKey(attribute.getName())) {
                    Set<String> values = requestAttrs.get(attribute.getName());
                    if (isEmptyAttribute(values)) {
                        // Check for required attributes
                        if (filter.isRequired(attribute)) {
                            throw new BadRequestException(attribute.getName() + " is not specified");
                        }
                        // If the key exists and the value is empty, delete the attribute.
                        groupAttrs.put(attribute.getName(), Collections.<String>emptySet());
                    } else {
                        groupAttrs.put(attribute.getName(), values);
                    }
                } else {
                    // Check for required attributes
                    if (filter.isRequired(attribute)) {
                        throw new BadRequestException(attribute.getName() + " is not specified");
                    }
                }
            }
        }

        // Adjust attribute values
        try {
            String agentType = schema.getName();
            AgentConfiguration.addAgentRootURLKey(agentType, groupAttrs, false);
        } catch (ConfigurationException e) {
            // Since no validation is performed, no exceptions will be raised
        }

        amid.setAttributes(groupAttrs);
        amid.store();
    }

    private JsonValue agentGroupToJsonValue(SSOToken adminToken, String realm, AMIdentity groupIdentity,
            Context context)
                    throws InternalServerErrorException {
        JsonValue result = json(object());

        try {
            Map<String, Set<String>> groupAttrs = getAgentAttributes(groupIdentity);

            converter.toJson(realm, groupAttrs, false, result);

            result.add(ResourceResponse.FIELD_CONTENT_ID, groupIdentity.getName());
            result.add("_type", getTypeValue(context).getObject());

        } catch (SSOException e) {
            debug.error("AgentGroupResourceProvider.agentGroupToJsonValue() :: "
                    + "Unable to retrieve agentgroup configuration", e);
            throw new InternalServerErrorException("Unable to retrieve agentgroup configuration");
        } catch (IdRepoException e) {
            debug.error("AgentGroupResourceProvider.agentGroupToJsonValue() :: "
                    + "Unable to retrieve agentgroup configuration", e);
            throw new InternalServerErrorException("Unable to retrieve agentgroup configuration");
        } catch (SMSException e) {
            debug.error("AgentGroupResourceProvider.agentGroupToJsonValue() :: "
                    + "Unable to retrieve agentgroup configuration", e);
            throw new InternalServerErrorException("Unable to retrieve agentgroup configuration");
        }

        return result;
    }

    private Set<AMIdentity> getAgentGroupIdentities(SSOToken adminToken, String name, String realm)
            throws SSOException, IdRepoException, BadRequestException, InternalServerErrorException {

        final AMIdentityRepository amIdRepo = new AMIdentityRepository(realm, adminToken);
        final IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);
        idsc.setMaxResults(0);
        final Map<String, Set<String>> attributeValuePair = new HashMap<String, Set<String>>();
        attributeValuePair.put(IdConstants.AGENT_TYPE, asSet(schema.getName()));
        idsc.setSearchModifiers(IdSearchOpModifier.AND, attributeValuePair);
        IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.AGENTGROUP, name, idsc, true, false);

        return searchResults != null ?
                (Set<AMIdentity>)searchResults.getSearchResults() : Collections.<AMIdentity>emptySet();
    }
}
