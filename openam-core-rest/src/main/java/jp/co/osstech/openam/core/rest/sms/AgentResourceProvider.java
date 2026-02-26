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
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.PROPERTY_ORDER;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.TITLE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.TYPE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.addAttributeSchema;
import static org.forgerock.openam.utils.CollectionUtils.asSet;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.collections.CollectionUtils;
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
 * REST resource for Agent Management.
 */
@RequestHandler
public class AgentResourceProvider extends AgentResourceProviderBase {

    private static final Set<String> NON_INHERITABLE_ATTRIBUTES =
            asSet(AgentConfiguration.ATTR_NAME_PWD, AgentConfiguration.ATTR_CONFIG_REPO,
                    AgentConfiguration.ATTR_NAME_GROUP);

    @Inject
    public AgentResourceProvider(@Assisted SmsJsonConverter converter, @Assisted ServiceSchema schema,
            @Assisted SchemaType type, @Assisted List<ServiceSchema> subSchemaPath, @Assisted String uriPath,
            @Assisted boolean serviceHasInstanceName, @Named("frRest") Debug debug,
            @Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache,
            @Named("DefaultLocale") Locale defaultLocale) {
        super(schema, type, subSchemaPath, uriPath, serviceHasInstanceName, converter, debug, resourceBundleCache,
                defaultLocale);
    }

    protected JsonValue createSchema(Context context) {
        JsonValue result = json(object(field(TYPE, OBJECT_TYPE)));
        if (supportsGroup()) {
            // Create schema with "inherited"
            addAttributeSchema(result, "/" + PROPERTIES + "/", schema, getLocale(context),
                    realmFor(context), true, NON_INHERITABLE_ATTRIBUTES,
                    new AgentAttributeSchemaFilter());

            // Replace the contents of agentgroup
            ResourceBundle rb = resourceBundleCache.getResBundle(schema.getI18NFileName(), getLocale(context));
            result.putPermissive(new JsonPointer(getAgentGroupPointerForSchema() + "/" + TITLE),
                    rb.getString("label.agentgroup"));
            result.putPermissive(new JsonPointer(getAgentGroupPointerForSchema() + "/" + PROPERTY_ORDER), 1);
        } else {
            addAttributeSchema(result, "/" + PROPERTIES + "/", schema, getLocale(context),
                    realmFor(context), false, null, new AgentAttributeSchemaFilter());
        }
        return result;
    }

    protected JsonValue createTemplate() {
        JsonValue result = json(object());
        Map<String, Set<String>> defaults = schema.getAttributeDefaults();

        // Workaround : The default value of AM_SERVER_PORT does not match syntax
        String agentType = schema.getName();
        String serverPort = null;
        if (AgentConfiguration.AGENT_TYPE_J2EE.equals(agentType)) {
            serverPort = defaults.get(AM_SERVER_PORT).iterator().next();
            defaults.put(AM_SERVER_PORT, asSet("0"));
        }

        if (supportsGroup()) {
            // Create template with "inherited"
            result = converter.toJson(null, defaults, false, true, NON_INHERITABLE_ATTRIBUTES,
                    new HashSet<String>(), result);

            // Add agentgroup
            result.putPermissive(new JsonPointer(getAgentGroupPointer()), null);
        } else {
            result = converter.toJson(null, defaults, false, false,
                    null, null, result);
        }

        // Workaround
        if (AgentConfiguration.AGENT_TYPE_J2EE.equals(agentType)) {
            result.putPermissive(new JsonPointer("/fam/" + AM_SERVER_PORT + "/value"),
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
            Set<String> inheritedAttributes = new HashSet<String>();
            Set<String> nonInheritedAttributes = new HashSet<String>();
            Map<String, Set<String>> requestAttrs = null;
            if (supportsGroup()) {
                // This request has inheritable values.
                requestAttrs = converter.fromJson(realm, content, true, NON_INHERITABLE_ATTRIBUTES,
                        inheritedAttributes, nonInheritedAttributes);
            } else {
                requestAttrs = converter.fromJson(realm, content, false, null, null, null);
            }
            ServiceConfigManager scm = getServiceConfigManager(context);

            final String agentName = content.get(ResourceResponse.FIELD_CONTENT_ID).asString();
            if (StringUtils.isEmpty(agentName)) {
                return new BadRequestException("Invalid name").asPromise();
            }

            String groupName = null;
            if (supportsGroup()) {
                JsonValue agentgroup = content.get(new JsonPointer(getAgentGroupPointer()));
                if (agentgroup != null) {
                    if (agentgroup.isString()) {
                        groupName = agentgroup.asString();
                    } else if (!agentgroup.isNull()) {
                        return new BadRequestException("Invalid attribute value syntax: '" + AgentConfiguration.ATTR_NAME_GROUP + "'")
                                .asPromise();
                    }
                }
            }

            createAgent(admin, realm, agentName, groupName, requestAttrs, inheritedAttributes);

            final ServiceConfig parentConfig = parentSubConfigFor(context, scm);

            return awaitCreation(context, agentName)
                    .then(new Function<Void, ResourceResponse, ResourceException>() {
                        @Override
                        public ResourceResponse apply(Void aVoid) {
                            JsonValue result = null;
                            try {
                                result = readAgent(admin, realm, agentName, parentConfig, context);
                            } catch (NotFoundException e) {
                                debug.warning("Error creating JsonValue", e);
                            } catch (InternalServerErrorException e) {
                                debug.warning("Error creating JsonValue", e);
                            }
                            return newResourceResponse(agentName, String.valueOf(result.hashCode()), result);
                        }
                    });
        } catch (SSOException e) {
            debug.error("AgentResourceProvider.createInstance() :: Cannot CREATE resource", e);
            return new InternalServerErrorException("Unable to create agent config").asPromise();
        } catch (IdRepoDuplicateObjectException e) {
            debug.error("AgentResourceProvider.createInstance() :: Cannot CREATE resource", e);
            return new ConflictException("Resource already exists").asPromise();
        } catch (IdRepoException e) {
            debug.error("AgentResourceProvider.createInstance() :: Cannot CREATE resource", e);
            return new InternalServerErrorException("Unable to create agent config").asPromise();
        } catch (SMSException e) {
            debug.error("AgentResourceProvider.createInstance() :: Cannot CREATE resource", e);
            return new InternalServerErrorException("Unable to create agent config").asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Read
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, String resourceId) {
        try {
            final SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            ServiceConfigManager scm = getServiceConfigManager(context);
            ServiceConfig parentConfig;
            try {
                parentConfig = parentSubConfigFor(context, scm);
            } catch (NotFoundException e) {
                // By default, there is no agent service in the sub realms.
                throw new NotFoundException();
            }
            checkedInstanceSubConfig(context, resourceId, parentConfig);

            JsonValue result = readAgent(admin, realmFor(context), resourceId, parentConfig, context);
            return newResultPromise(newResourceResponse(resourceId, String.valueOf(result.hashCode()), result));
        } catch (SSOException e) {
            debug.error("AgentResourceProvider.readInstance() :: Cannot READ resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to read agent config").asPromise();
        } catch (SMSException e) {
            debug.error("AgentResourceProvider.readInstance() :: Cannot READ resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to read agent config").asPromise();
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
            Set<String> inheritedAttributes = new HashSet<String>();
            Set<String> nonInheritedAttributes = new HashSet<String>();
            Map<String, Set<String>> requestAttrs = null;
            if (supportsGroup()) {
                // This request has inheritable values.
                requestAttrs = converter.fromJson(realm, content, true, NON_INHERITABLE_ATTRIBUTES,
                        inheritedAttributes, nonInheritedAttributes);
            } else {
                requestAttrs = converter.fromJson(realm, content, false, null, null, null);
            }
            ServiceConfigManager scm = getServiceConfigManager(context);
            ServiceConfig parentConfig;
            try {
                parentConfig = parentSubConfigFor(context, scm);
            } catch (NotFoundException e) {
                // By default, there is no agent service in the sub realms.
                throw new NotFoundException();
            }

            checkedInstanceSubConfig(context, resourceId, parentConfig);

            // "groupName" is treated as follows:
            // * null (If the key does not exist) -> Keep current value
            // * empty string (If the key exists but the value is empty) -> Delete the value
            // * other -> Update to specified value
            String groupName = null;
            if (supportsGroup()) {
                JsonValue agentgroup = content.get(new JsonPointer(getAgentGroupPointer()));
                if (agentgroup != null) {
                    if (agentgroup.isString()) {
                        groupName = agentgroup.asString();
                    } else if (agentgroup.isNull()) {
                        groupName = new String();
                    } else {
                        return new BadRequestException("Invalid attribute value syntax: '" + AgentConfiguration.ATTR_NAME_GROUP + "'")
                                .asPromise();
                    }
                }
            }

            updateAgent(admin, realm, resourceId, groupName, requestAttrs, inheritedAttributes, nonInheritedAttributes);

            JsonValue result = readAgent(admin, realm, resourceId, parentConfig, context);
            return newResultPromise(newResourceResponse(resourceId, String.valueOf(result.hashCode()), result));
        } catch (SMSException e) {
            debug.error("AgentResourceProvider.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to update agent config").asPromise();
        } catch (SSOException e) {
            debug.error("AgentResourceProvider.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to update agent config").asPromise();
        } catch (IdRepoException e) {
            debug.error("AgentResourceProvider.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to update agent config").asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Delete
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context, final String resourceId) {
        try {
            ServiceConfigManager scm = getServiceConfigManager(context);
            ServiceConfig parentConfig;
            try {
                parentConfig = parentSubConfigFor(context, scm);
            } catch (NotFoundException e) {
                // By default, there is no agent service in the sub realms.
                throw new NotFoundException();
            }
            checkedInstanceSubConfig(context, resourceId, parentConfig);

            parentConfig.removeSubConfig(resourceId);

            return awaitDeletion(context, resourceId)
                    .then(new Function<Void, ResourceResponse, ResourceException>() {
                        @Override
                        public ResourceResponse apply(Void aVoid) {
                            return newResourceResponse(resourceId, "0", json(object(field("success", true))));
                        }
                    });
        } catch (SMSException e) {
            debug.error("AgentResourceProvider.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to delete agent config").asPromise();
        } catch (SSOException e) {
            debug.error("AgentResourceProvider.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to delete agent config").asPromise();
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

            String agentName = null;
            if (queryFilter != null) {
                agentName = "*";
            } else {
                agentName = request.getQueryId();
                if (agentName == null || agentName.isEmpty()) {
                    agentName = "*";
                }
            }

            String realm = realmFor(context);
            Set<AMIdentity> agents = getAgentIdentitiies(admin, agentName, realm);

            ServiceConfigManager scm = getServiceConfigManager(context);
            ServiceConfig parentConfig;
            try {
                parentConfig = parentSubConfigFor(context, scm);
            } catch (NotFoundException e) {
                // By default, there is no agent service in the sub realms.
                parentConfig = null;
            }
            List<ResourceResponse> results = new ArrayList<>();
            if (parentConfig != null) {
                for (AMIdentity agent : agents) {
                    JsonValue result = agentToJsonValue(admin, realm, agent, context);
                    results.add(newResourceResponse(agent.getName(), "0", result));
                }
            }

            return QueryResponsePresentation.perform(handler, request, results);
        } catch (SMSException e) {
            debug.error("AgentResourceProvider.queryCollection() :: Cannot QUERY resources", e);
            return new InternalServerErrorException("Unable to query agent config").asPromise();
        } catch (SSOException e) {
            debug.error("AgentResourceProvider.queryCollection() :: Cannot QUERY resources", e);
            return new InternalServerErrorException("Unable to query agent config").asPromise();
        } catch (IdRepoException e) {
            debug.error("AgentResourceProvider.queryCollection() :: Cannot QUERY resources", e);
            return new InternalServerErrorException("Unable to query agent config").asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    private void createAgent(SSOToken adminToken, String realm, String agentName, String groupName,
            Map<String, Set<String>> requestAttrs, Set<String> inheritedAttributes)
                    throws SSOException, IdRepoException, BadRequestException, InternalServerErrorException {

        Map<String, Set<String>> agentAttrs = new HashMap<String, Set<String>>();

        // Check for required attributes
        AttributeSchemaFilter filter = new AgentAttributeSchemaFilter();
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
        // Workaround : The default value of DEVICE_KEY does not match URL format
        if ((AgentConfiguration.AGENT_TYPE_WEB.equals(agentType)
                || AgentConfiguration.AGENT_TYPE_J2EE.equals(agentType))
                && isEmptyAttribute(requestAttrs.get(AgentConfiguration.DEVICE_KEY))) {
            tmpAttrs.put(AgentConfiguration.DEVICE_KEY, Collections.<String>emptySet());
        }
        tmpAttrs.putAll(requestAttrs);

        // Filter out invalid attributes
        for (String attributeName : tmpAttrs.keySet()) {
            final AttributeSchema attributeSchema = schema.getAttributeSchema(attributeName);
            if (filter.isTarget(attributeSchema)) {
                agentAttrs.put(attributeName, tmpAttrs.get(attributeName));
            }
        }

        // Check for AgentGroup
        if (supportsGroup()) {
            if (groupName != null) {
                if (!groupExists(adminToken, groupName, realm)) {
                    throw new BadRequestException("'" + AgentConfiguration.ATTR_NAME_GROUP + "' attribute is invalid.");
                }
                agentAttrs.put(AgentConfiguration.ATTR_NAME_GROUP, asSet(groupName));

                for (String inheritedAttribute : inheritedAttributes) {
                    agentAttrs.remove(inheritedAttribute);
                }

                if (supporsLocation()) {
                    // Agents with local configuration do not support groups
                    String location = CollectionUtils.isNotEmpty(agentAttrs.get(AgentConfiguration.ATTR_CONFIG_REPO)) ?
                            agentAttrs.get(AgentConfiguration.ATTR_CONFIG_REPO).iterator().next() : null;
                    if (location.equalsIgnoreCase("local")) {
                        throw new BadRequestException(
                                "Unable to add agent to group because agent's properties are stored locally");
                    }
                }
            }
        }

        // Adjust attribute values
        try {
            AgentConfiguration.addAgentRootURLKey(agentType, agentAttrs, true);
        } catch (ConfigurationException e) {
            throw new BadRequestException("'" + AgentConfiguration.DEVICE_KEY + "' attribute is invalid.");
        }

        // Put AgentType
        agentAttrs.put(IdConstants.AGENT_TYPE, asSet(schema.getName()));

        AMIdentityRepository amir = new AMIdentityRepository(realm, adminToken);
        amir.createIdentity(IdType.AGENTONLY, agentName, agentAttrs);
    }

    private JsonValue readAgent(SSOToken adminToken, String realm, String resourceId, ServiceConfig parentConfig,
            Context context)
                    throws InternalServerErrorException, NotFoundException {

        AMIdentity agentOnlyIdentity = new AMIdentity(adminToken, resourceId,
                IdType.AGENTONLY, realm, null);

        return agentToJsonValue(adminToken, realm, agentOnlyIdentity, context);
    }

    private void updateAgent(SSOToken adminToken, String realm, String agentName, String groupName,
            Map<String, Set<String>> requestAttrs, Set<String> inheritedAttributes,
            Set<String> nonInheritedAttributes)
                    throws SSOException, IdRepoException, SMSException, NotFoundException,
                        BadRequestException, InternalServerErrorException {

        AMIdentity amid = new AMIdentity(adminToken, agentName, IdType.AGENTONLY, realm, null);
        Map<String, Set<String>> agentAttrs = getAgentAttributes(amid);

        // Filter out invalid attributes
        AttributeSchemaFilter filter = new AgentAttributeSchemaFilter();
        for (AttributeSchema attribute : schema.getAttributeSchemas()) {
            if (filter.isTarget(attribute)) {
                if (requestAttrs.containsKey(attribute.getName())) {
                    Set<String> values = requestAttrs.get(attribute.getName());
                    if (isEmptyAttribute(values)) {
                        // Check for required attributes (Except for passwords)
                        if (filter.isRequired(attribute)) {
                            if (!AgentConfiguration.ATTR_NAME_PWD.equals(attribute.getName())) {
                                throw new BadRequestException(attribute.getName() + " is not specified");
                            }
                        } else {
                            // If the key exists and the value is empty, delete the attribute.
                            agentAttrs.put(attribute.getName(), Collections.<String>emptySet());
                        }
                    } else {
                        agentAttrs.put(attribute.getName(), values);
                    }
                } else {
                    // Check for required attributes (Except for passwords)
                    if (filter.isRequired(attribute)
                            && !(AgentConfiguration.ATTR_NAME_PWD.equals(attribute.getName()))) {
                        throw new BadRequestException(attribute.getName() + " is not specified");
                    }
                }
            }
        }

        // Check for AgentGroup
        if (supportsGroup()) {
            AMIdentity currentGroup = null;
            Set<String> groupAttrValues = agentAttrs.get(AgentConfiguration.ATTR_NAME_GROUP);
            String currentGroupName = groupAttrValues != null && groupAttrValues.size() > 0 ?
                    groupAttrValues.iterator().next() : null;
            if (currentGroupName != null) {
                currentGroup = getGroupIdentity(adminToken, currentGroupName, realm);
            }

            if (groupName != null) {
                if (!groupName.isEmpty()) {
                    if (!groupExists(adminToken, groupName, realm)) {
                        throw new BadRequestException("'" + AgentConfiguration.ATTR_NAME_GROUP + "' attribute is invalid.");
                    }
                    agentAttrs.put(AgentConfiguration.ATTR_NAME_GROUP, asSet(groupName));

                    // Adjust inherited attributes
                    adjustInheritedAttributes(amid, currentGroup, inheritedAttributes, nonInheritedAttributes, agentAttrs, false);
                } else {
                    // Delete "agentgroup" attribute
                    if (currentGroupName != null) {
                        agentAttrs.put(AgentConfiguration.ATTR_NAME_GROUP, Collections.<String>emptySet());

                        // Adjust inherited attributes
                        adjustInheritedAttributes(amid, currentGroup, Collections.<String>emptySet(), Collections.<String>emptySet(),
                                agentAttrs, true);
                    }
                }
            } else {
                // Keep current value of "agentgroup"
                if (currentGroupName != null) {
                    // Adjust inherited attributes
                    adjustInheritedAttributes(amid, currentGroup, inheritedAttributes, nonInheritedAttributes, agentAttrs, false);
                }
            }
        }

        // Adjust attribute values
        try {
            String agentType = schema.getName();
            AgentConfiguration.addAgentRootURLKey(agentType, agentAttrs, true);
        } catch (ConfigurationException e) {
            throw new BadRequestException("'" + AgentConfiguration.DEVICE_KEY + "' attribute is invalid.");
        }

        amid.setAttributes(agentAttrs);
        amid.store();
    }

    private JsonValue agentToJsonValue(SSOToken adminToken, String realm, AMIdentity agentOnlyIdentity,
            Context context)
                    throws InternalServerErrorException, NotFoundException {
        JsonValue result = json(object());

        try {
            Map<String, Set<String>> agentAttrs = getAgentAttributes(agentOnlyIdentity);

            if (supportsGroup()) {
                Set<String> inheritedAttributes = new HashSet<String>();

                Set<String> groups = agentAttrs.get(AgentConfiguration.ATTR_NAME_GROUP);
                String groupname = groups != null && groups.size() > 0 ?
                        groups.iterator().next() : null;

                if (groupname != null) {
                    AMIdentity agentGroup = new AMIdentity(adminToken, groupname,
                            IdType.AGENTGROUP, realm, null);
                    if (!matchAgentType(agentGroup)) {
                        throw new NotFoundException();
                    }
                    Map<String, Set<String>> groupAttrs = getAgentAttributes(agentGroup);
                    groupAttrs.putAll(agentAttrs);
                    agentAttrs = groupAttrs;

                    inheritedAttributes = AgentConfiguration.getInheritedAttributeNames(agentOnlyIdentity);
                }

                // The response has inheritable values.
                converter.toJson(realm, agentAttrs, false, true, NON_INHERITABLE_ATTRIBUTES,
                        inheritedAttributes, result);

                // Add the contents of agentgroup
                result.putPermissive(new JsonPointer(getAgentGroupPointer()), groupname);
            } else {
                converter.toJson(realm, agentAttrs, false, false, null, null, result);
            }

            result.add(ResourceResponse.FIELD_CONTENT_ID, agentOnlyIdentity.getName());
            result.add("_type", getTypeValue(context).getObject());

        } catch (SSOException e) {
            debug.error("AgentResourceProvider.agentToJsonValue() :: Unable to retrieve agent configuration", e);
            throw new InternalServerErrorException("Unable to retrieve agent configuration");
        } catch (IdRepoException e) {
            debug.error("AgentResourceProvider.agentToJsonValue() :: Unable to retrieve agent configuration", e);
            throw new InternalServerErrorException("Unable to retrieve agent configuration");
        } catch (SMSException e) {
            debug.error("AgentResourceProvider.agentToJsonValue() :: Unable to retrieve agent configuration", e);
            throw new InternalServerErrorException("Unable to retrieve agent configuration");
        }

        return result;
    }

    private void adjustInheritedAttributes(AMIdentity agent, AMIdentity currentGroup,
            Set<String> inheritedAttributes, Set<String> nonInheritedAttributes,
            Map<String, Set<String>> agentAttrs, boolean leaveGroup)
                    throws SSOException, IdRepoException, SMSException, BadRequestException {

        Set<String> currentInheritedAttributes = new HashSet<String>();
        Set<String> currentNonInheritedAttributes = new HashSet<String>();

        if (supporsLocation()) {
            // Agents with local configuration do not support groups
            String newLocation = CollectionUtils.isNotEmpty(agentAttrs.get(AgentConfiguration.ATTR_CONFIG_REPO)) ?
                    agentAttrs.get(AgentConfiguration.ATTR_CONFIG_REPO).iterator().next() : null;
            if ("local".equalsIgnoreCase(newLocation)) {
                throw new BadRequestException(
                        "Unable to add agent to group because agent's properties are stored locally");
            }

            // Local agent does not support agent group, so inherited attributes don't exist.
            Map<String, Set<String>> currentAttrs = getAgentAttributes(agent);
            String currentLocation = CollectionUtils.isNotEmpty(currentAttrs.get(AgentConfiguration.ATTR_CONFIG_REPO)) ?
                    currentAttrs.get(AgentConfiguration.ATTR_CONFIG_REPO).iterator().next() : null;
            if (!"local".equalsIgnoreCase(currentLocation)) {
                currentInheritedAttributes = AgentConfiguration.getInheritedAttributeNames(agent);
            }
            currentNonInheritedAttributes = currentAttrs.keySet();
        } else {
            currentInheritedAttributes = AgentConfiguration.getInheritedAttributeNames(agent);
            currentNonInheritedAttributes = getAgentAttributes(agent).keySet();
        }

        Set<String> fromSelf;
        Set<String> fromGroup;
        if (leaveGroup) {
            fromSelf = new HashSet<String>(currentInheritedAttributes);
            fromGroup = new HashSet<String>();
        } else {
            fromSelf = new HashSet<String>(nonInheritedAttributes);
            fromSelf.removeAll(currentNonInheritedAttributes);
            fromGroup = new HashSet<String>(inheritedAttributes);
            fromGroup.removeAll(currentInheritedAttributes);
        }

        Map<String, Set<String>> currentInheritedValues =
                currentGroup != null ? currentGroup.getAttributes() : schema.getAttributeDefaults();
        for (String attributeName : fromSelf) {
            // AMHashMap does not support "putIfAbsent()"
            if (!agentAttrs.containsKey(attributeName)) {
                agentAttrs.put(attributeName, currentInheritedValues.get(attributeName));
            }
        }
        if (!fromGroup.isEmpty()) {
            agent.removeAttributes(fromGroup);
        }
        for (String inheritedAttribute : inheritedAttributes) {
            agentAttrs.remove(inheritedAttribute);
        }
    }

    private boolean supportsGroup() {
        AttributeSchema attributeSchema = schema.getAttributeSchema(AgentConfiguration.ATTR_NAME_GROUP);
        return attributeSchema != null ? true : false;
    }

    private boolean supporsLocation() {
        AttributeSchema attributeSchema = schema.getAttributeSchema(AgentConfiguration.ATTR_CONFIG_REPO);
        return attributeSchema != null ? true : false;
    }

    private AMIdentity getGroupIdentity(SSOToken adminToken, String groupName, String realm)
            throws SSOException, IdRepoException {

        AMIdentity group = new AMIdentity(adminToken, groupName, IdType.AGENTGROUP, realm, null);
        if (!group.isExists()) {
            return null;
        }
        if (!matchAgentType(group)) {
            return null;
        }

        return group;
    }

    private boolean groupExists(SSOToken adminToken, String groupName, String realm)
            throws SSOException, IdRepoException {

        return getGroupIdentity(adminToken, groupName, realm) != null;
    }

    private Set<AMIdentity> getAgentIdentitiies(SSOToken adminToken, String name, String realm)
            throws SSOException, IdRepoException, BadRequestException, InternalServerErrorException {

        final AMIdentityRepository amIdRepo = new AMIdentityRepository(realm, adminToken);
        final IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);
        idsc.setMaxResults(0);
        final Map<String, Set<String>> attributeValuePair = new HashMap<String, Set<String>>();
        attributeValuePair.put(IdConstants.AGENT_TYPE, asSet(schema.getName()));
        idsc.setSearchModifiers(IdSearchOpModifier.AND, attributeValuePair);
        IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.AGENTONLY, name, idsc, true, false);

        return searchResults != null ?
                (Set<AMIdentity>)searchResults.getSearchResults() : Collections.<AMIdentity>emptySet();
    }

    private String getAgentGroupPointer() {
        // WebAgent and J2EEAgent have global section for agentgroup attribute
        String agentType = schema.getName();
        if (AgentConfiguration.AGENT_TYPE_WEB.equals(agentType)
                || AgentConfiguration.AGENT_TYPE_J2EE.equals(agentType)) {
            return "/global/" + AgentConfiguration.ATTR_NAME_GROUP;
        }
        return "/" + AgentConfiguration.ATTR_NAME_GROUP;
    }

    private String getAgentGroupPointerForSchema() {
        // WebAgent and J2EEAgent have global section for agentgroup attribute
        String agentType = schema.getName();
        if (AgentConfiguration.AGENT_TYPE_WEB.equals(agentType)
                || AgentConfiguration.AGENT_TYPE_J2EE.equals(agentType)) {
            return "/properties/global/properties/" + AgentConfiguration.ATTR_NAME_GROUP;
        }
        return "/properties/" + AgentConfiguration.ATTR_NAME_GROUP;
    }

    private boolean matchAgentType(AMIdentity amIdentity) throws SSOException, IdRepoException {
        Set types = amIdentity.getAttribute(IdConstants.AGENT_TYPE);
        if (types != null && types.contains(schema.getName())) {
            return true;
        }
        return false;
    }
}
