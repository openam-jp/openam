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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2019-2026 OSSTech Corporation
 */

package org.forgerock.openam.core.rest.sms;

import static org.forgerock.json.JsonValue.*;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.*;
import static org.forgerock.openam.rest.RestConstants.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

import org.forgerock.guava.common.collect.BiMap;
import org.forgerock.guava.common.collect.HashBiMap;
import org.forgerock.http.routing.UriRouterContext;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.annotations.Action;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.resource.LocaleContext;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.config.AMAuthenticationManager;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import com.sun.identity.sm.ServiceSchema;
import com.sun.identity.sm.ServiceSchemaManager;

/**
 * A base class for resource providers for the REST SMS services - provides common utility methods for
 * navigating SMS schemas. It implements basic functionality such as reading of schema, template and
 * creatable types, while allowing all of those mechanisms to be overridden by more specific subclasses.
 * @since 13.0.0
 */
public abstract class SmsResourceProvider {

    /**
     * Contains the mapping of auto created authentication modules and their type so that
     * requests to the authentication module endpoint can check if they need to check the
     * special place that these auto created modules are stored.
     */
    static final BiMap<String, String> AUTO_CREATED_AUTHENTICATION_MODULES = HashBiMap.create(7);

    static {
        AUTO_CREATED_AUTHENTICATION_MODULES.put("hotp", "hotp");
        AUTO_CREATED_AUTHENTICATION_MODULES.put("sae", "sae");
        AUTO_CREATED_AUTHENTICATION_MODULES.put("oath", "oath");
        AUTO_CREATED_AUTHENTICATION_MODULES.put("ldap", "ldap");
        AUTO_CREATED_AUTHENTICATION_MODULES.put("datastore", "datastore");
        AUTO_CREATED_AUTHENTICATION_MODULES.put("federation", "federation");
        AUTO_CREATED_AUTHENTICATION_MODULES.put("wssauthmodule", "wssauth");
    }

    protected final String serviceName;
    protected final String serviceVersion;
    protected final List<ServiceSchema> subSchemaPath;
    protected final SchemaType type;
    protected final boolean hasInstanceName;
    protected final List<String> uriPath;
    protected final SmsJsonConverter converter;
    protected final Debug debug;
    protected final ServiceSchema schema;
    protected final AMResourceBundleCache resourceBundleCache;
    protected final Locale defaultLocale;

    SmsResourceProvider(ServiceSchema schema, SchemaType type, List<ServiceSchema> subSchemaPath, String uriPath,
            boolean serviceHasInstanceName, SmsJsonConverter converter, Debug debug,
            AMResourceBundleCache resourceBundleCache, Locale defaultLocale) {
        this.schema = schema;
        this.serviceName = schema.getServiceName();
        this.serviceVersion = schema.getVersion();
        this.type = type;
        this.subSchemaPath = subSchemaPath;
        this.uriPath = uriPath == null ? Collections.<String>emptyList() : Arrays.asList(uriPath.split("/"));
        this.hasInstanceName = serviceHasInstanceName;
        this.converter = converter;
        this.debug = debug;
        this.resourceBundleCache = resourceBundleCache;
        this.defaultLocale = defaultLocale;
    }

    /**
     * Gets the realm from the underlying RealmContext.
     * @param context The Context for the request.
     * @return The resolved realm.
     */
    protected String realmFor(Context context) {
        return context.containsContext(RealmContext.class) ?
                context.asContext(RealmContext.class).getResolvedRealm() : null;
    }

    /**
     * Gets a {@link com.sun.identity.sm.ServiceConfigManager} using the {@link SSOToken} available from the request
     * context.
     * @param context The request's context.
     * @return A newly-constructed {@link ServiceConfigManager} for the appropriate {@link #serviceName} and
     * {@link #serviceVersion}.
     * @throws SMSException From downstream service manager layer.
     * @throws SSOException From downstream service manager layer.
     */
    protected ServiceConfigManager getServiceConfigManager(Context context) throws SSOException, SMSException {
        SSOToken ssoToken = context.asContext(SSOTokenContext.class).getCallerSSOToken();
        return new ServiceConfigManager(ssoToken, serviceName, serviceVersion);
    }

    /**
     * Gets the ServiceConfig parent of the parent of the config being addressed by the current request.
     * @param context The request context, from which the path variables can be retrieved.
     * @param scm The {@link com.sun.identity.sm.ServiceConfigManager}. See {@link #getServiceConfigManager(Context)}.
     * @return The ServiceConfig that was found.
     * @throws SMSException From downstream service manager layer.
     * @throws SSOException From downstream service manager layer.
     * @throws NotFoundException When some configuration in the parent path does not exist.
     */
    protected ServiceConfig parentSubConfigFor(Context context, ServiceConfigManager scm)
            throws SMSException, SSOException, NotFoundException {

        Map<String, String> uriTemplateVariables = getUriTemplateVariables(context);

        ServiceConfig config;
        if (type == SchemaType.GLOBAL) {
            config = scm.getGlobalConfig(hasInstanceName ? uriTemplateVariables.get("name") : null);
        } else {
            config = scm.getOrganizationConfig(realmFor(context), null);
            if (!SmsRequestHandler.USE_PARENT_PATH.equals(schema.getResourceName()) && !config.exists()) {
                throw new NotFoundException("Parent service does not exist.");
            }
        }

        for (int i = 0; i < subSchemaPath.size() - 1; i++) {
            ServiceSchema schema = subSchemaPath.get(i);
            String subConfigName = schema.getResourceName();

            boolean configNeedsToExist = true;
            if (subConfigName == null || SmsRequestHandler.USE_PARENT_PATH.equals(subConfigName)) {
                subConfigName = schema.getName();
                configNeedsToExist = false;
            }

            if (uriPath.contains("{" + subConfigName + "}")) {
                subConfigName = uriTemplateVariables.get(subConfigName);
                configNeedsToExist = true;
            }

            config = config.getSubConfig(subConfigName);

            if (configNeedsToExist && !config.exists()) {
                throw new NotFoundException("Parent subconfig of type " + subConfigName + " does not exist.");
            }
        }
        return config;
    }

    static Map<String, String> getUriTemplateVariables(Context context) {
        Map<String, String> uriTemplateVariables = new HashMap<>();
        Context c = context;
        while (c.containsContext(UriRouterContext.class)) {
            uriTemplateVariables.putAll(c.asContext(UriRouterContext.class).getUriTemplateVariables());
            c = c.getParent();
        }
        return uriTemplateVariables;
    }

    /**
     * Retrieves the {@link ServiceConfig} instance for the provided resource ID within the provided ServiceConfig
     * parent instance, and checks whether it exists.
     * @param context The request context.
     * @param resourceId The identifier for the config.
     * @param config The parent config instance.
     * @return The found instance.
     * @throws SMSException From downstream service manager layer.
     * @throws SSOException From downstream service manager layer.
     * @throws NotFoundException If the ServiceConfig does not exist.
     */
    protected ServiceConfig checkedInstanceSubConfig(Context context, String resourceId, ServiceConfig config)
            throws SSOException, SMSException, NotFoundException {
        if (config.getSubConfigNames().contains(resourceId)) {
            ServiceConfig subConfig = config.getSubConfig(resourceId);
            if (subConfig == null || !subConfig.getSchemaID().equals(lastSchemaNodeName()) || !subConfig.exists()) {
                throw new NotFoundException();
            }
            return subConfig;
        } else {
            /*
             * Use case: The default created auth modules on a fresh install aren't stored in the same
             * place as auth modules created by the user. Therefore if the auth module is not found in
             * the organisation schema we need to check if is one of these auth created modules.
             */
            if (!isDefaultCreatedAuthModule(context, resourceId) || !config.exists()) {
                throw new NotFoundException();
            }
            return config;
        }
    }

    boolean isDefaultCreatedAuthModule(Context context, String resourceId) throws SSOException,
            SMSException {
        String lastedMatchedUri = context.asContext(UriRouterContext.class).getMatchedUri();
        return AMAuthenticationManager.getAuthenticationServiceNames().contains(serviceName)
               && resourceId.equalsIgnoreCase(lastedMatchedUri);
    }

    /**
     * Gets the name of the last schema node in the {@link #subSchemaPath}.
     */
    protected String lastSchemaNodeName() {
        return schema.getName();
    }

    @Action
    public Promise<ActionResponse, ResourceException> schema(Context context) {
        return newActionResponse(createSchema(context)).asPromise();
    }

    @Action
    public Promise<ActionResponse, ResourceException> template() {
        return newActionResponse(createTemplate()).asPromise();
    }

    /**
     * Creates json response with attribute defaults when the service has global or default/realm schema.
     *
     * @return json response data; empty json if the service has only dynamic schema
     */
    protected JsonValue createTemplate() {
        if (serviceHasDefaultOrGlobalSchema()) {
            //when retrieving the template we don't want to validate the attributes
            return converter.toJson(schema.getAttributeDefaults(), false);
        }
        // Dynamic attributes default values will be added to the JSON response in the child class SmsSingletonProvider
        return json(object());
    }

    @Action
    public Promise<ActionResponse, ResourceException> getType(Context context) {
        try {
            return newActionResponse(getTypeValue(context)).asPromise();
        } catch (SMSException | SSOException e) {
            return new InternalServerErrorException("Could not get service schema", e).asPromise();
        }
    }

    protected JsonValue getTypeValue(Context context) throws SSOException, SMSException {
        String resourceId = schema.getResourceName();
        for (int i = subSchemaPath.size() - 1; i >= 0 && SmsRequestHandler.USE_PARENT_PATH.equals(resourceId); i--) {
            resourceId = subSchemaPath.get(i).getResourceName();
        }
        if (SmsRequestHandler.USE_PARENT_PATH.equals(resourceId)) {
            SSOToken ssoToken = context.asContext(SSOTokenContext.class).getCallerSSOToken();
                resourceId = new ServiceSchemaManager(ssoToken, serviceName, serviceVersion).getResourceName();
        }
        return json(object(
                field(ResourceResponse.FIELD_CONTENT_ID, resourceId),
                field(NAME, getI18NName(getLocale(context))),
                field(COLLECTION, schema.supportsMultipleConfigurations())));
    }
    
    private String getI18NName(Locale locale) {
        String i18nKey = schema.getI18NKey();
        String i18nName = schema.getName();
        if (StringUtils.isEmpty(i18nName)) {
            i18nName = schema.getServiceName();
        }
        ResourceBundle rb = resourceBundleCache.getResBundle(schema.getI18NFileName(), locale);
        if (rb != null && StringUtils.isNotEmpty(i18nKey)) {
            i18nName = com.sun.identity.shared.locale.Locale.getString(rb, i18nKey, debug);
        }
        return i18nName;
    }

    private JsonValue createSchema(Context context) {
        JsonValue result = json(object(field("type", "object")));
        addGlobalSchema(context, result);
        addOrganisationSchema(context, result);
        addDynamicSchema(context, result);
        return result;
    }

    /**
     * Add the global attribute schema to the given {@link JsonValue} result.
     *
     * @param context The request context.
     * @param result The response body {@link JsonValue}.
     */
    protected void addGlobalSchema(Context context, JsonValue result) {
        if (schema.getServiceType().equals(SchemaType.GLOBAL)) {
            addAttributeSchema(result, "/" + PROPERTIES + "/", schema, getLocale(context),
                    realmFor(context));
        }
    }

    /**
     * Add the organisation attribute schema to the given {@link JsonValue} result. The organisation attribute schema
     * will be added at the root of the JSON response if the request is for realm based schema, but should be added
     * under "defaults" when the request is for global schema, see {@link SmsGlobalSingletonProvider}.
     *
     * @param context The request context.
     * @param result The response body {@link JsonValue}.
     */
    protected void addOrganisationSchema(Context context, JsonValue result) {
        if (schema.getServiceType().equals(SchemaType.ORGANIZATION)) {
            addAttributeSchema(result, "/" + PROPERTIES + "/", schema, getLocale(context),
                    realmFor(context));
        }
    }

    /**
     * Add the dynamic attribute schema to the given {@link JsonValue} result.
     *
     * @param context The request context.
     * @param result The response body {@link JsonValue}.
     */
    protected void addDynamicSchema(Context context, JsonValue result) {
        // Dynamic schema will be added in SmsSingletonProvider
    }

    /**
     * Add the global attributes to the given {@link JsonValue} result.
     *
     * @param config The SMS config from which to read the attributes.
     * @param result The response body {@link JsonValue}.
     */
    @SuppressWarnings("unchecked")
    protected void addGlobalAttributes(ServiceConfig config, JsonValue result) {
        if (schema.getServiceType().equals(SchemaType.GLOBAL) && config != null) {
            converter.toJson(config.getAttributes(), false, result);
        }
    }

    /**
     * Add the organisation attributes to the given {@link JsonValue} result. The organisation attributes will be
     * added at the root of the JSON response if the request is for realm based attributes, but should be added
     * under "defaults" when the request is for global attributes, see {@link SmsGlobalSingletonProvider}.
     *
     * @param realm The realm/organisation where the attributes are stored.
     * @param config The SMS config from which to read the attributes.
     * @param result The response body {@link JsonValue}.
     */
    @SuppressWarnings("unchecked")
    protected void addOrganisationAttributes(String realm, ServiceConfig config, JsonValue result) {
        if (schema.getServiceType().equals(SchemaType.ORGANIZATION) && config != null) {
            converter.toJson(realm, config.getAttributes(), false, result);
        }
    }

    /**
     * Add the dynamic attributes to the given {@link JsonValue} result.
     *
     * @param realm The realm/organisation where the attributes are stored.
     * @param result The response body {@link JsonValue}.
     */
    protected void addDynamicAttributes(String realm, JsonValue result) {
        // Dynamic attributes will be added in SmsSingletonProvider
    }

    /**
     * Returns the JsonValue representation of the ServiceConfig using the {@link #converter}. Adds a {@code _id}
     * property for the name of the config.
     */
    protected final JsonValue getJsonValue(String realm, ServiceConfig config, Context context) throws
            InternalServerErrorException {
        return getJsonValue(realm, config, context, null, false);
    }

    /**
     * Returns the JsonValue representation of the ServiceConfig using the {@link #converter}. Adds a {@code _id}
     * property for the name of the config.
     */
    protected final JsonValue getJsonValue(String realm, ServiceConfig config, Context context,
            String authModuleResourceName, boolean autoCreatedAuthModule) throws InternalServerErrorException {
        JsonValue value = json(object());

        addGlobalAttributes(config, value);
        addOrganisationAttributes(realm, config, value);
        addDynamicAttributes(realm, value);

        String id = (null != config) ? config.getName() : "";
        if (autoCreatedAuthModule && StringUtils.isEmpty(id)) {
            id = AUTO_CREATED_AUTHENTICATION_MODULES.inverse().get(authModuleResourceName);
        }
        value.add("_id", id);
        try {
            value.add("_type", getTypeValue(context).getObject());
        } catch (SSOException | SMSException e) {
            debug.error("Error reading type for " + authModuleResourceName, e);
            throw new InternalServerErrorException();
        }
        return value;
    }

    protected boolean serviceHasDefaultOrGlobalSchema() {
        return !schema.getServiceType().equals(SchemaType.DYNAMIC);
    }

    protected Locale getLocale(Context context) {
        return context.asContext(LocaleContext.class).getLocale();
    }
}
