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
package jp.co.osstech.openam.core.rest.identities;

import static org.forgerock.json.JsonValue.*;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.rest.RestConstants.*;
import static org.forgerock.openam.rest.RestUtils.realmFor;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.CollectionResourceProvider;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.DeleteRequest;
import org.forgerock.json.resource.ForbiddenException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.openam.rest.resource.LocaleContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceManager;

/**
 * REST resource for User's Service.
 */
public class UserServiceResource implements CollectionResourceProvider {

    private static Debug logger = Debug.getInstance("frRest");
    private final ContextHelper contextHelper;
    private final Map<String, UserServiceHandler> handlers;

    @Inject
    public UserServiceResource(@Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache,
            ContextHelper helper) {
        this.contextHelper = helper;
        handlers = createServiceHandlers(resourceBundleCache);
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionCollection(Context context, ActionRequest request) {
        final String realm = realmFor(context);
        String userName = contextHelper.getUserId(context);

        AMIdentity user = getIdentity(userName, realm);
        if (user == null) {
            return new NotFoundException("Resource not found").asPromise();
        }
        if (UserUtils.isDsameUser(user) || UserUtils.isURLAccessAgent(user)) {
            return new ForbiddenException("Request is forbidden for this user").asPromise();
        }
        if (UserUtils.isAmAdminUser(user) || UserUtils.isAnonymousUser(user)) {
            return newActionResponse(json(object(field(RESULT, array())))).asPromise();
        }

        try {
            switch (request.getAction()) {
                case GET_ALL_TYPES:
                    return newActionResponse(getAllTypes(context)).asPromise();
                case GET_CREATABLE_TYPES:
                    return newActionResponse(getCreatableTypes(context, user)).asPromise();
                case NEXT_DESCENDENTS:
                    return newActionResponse(getNextDescendents(context, user, realm)).asPromise();
                default:
            }
        } catch (ResourceException e) {
            return e.asPromise();
        }

        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionInstance(Context context, String resourceId,
            ActionRequest request) {
        final String action = request.getAction();

        try {
            switch (request.getAction()) {
                case TEMPLATE:
                    return newActionResponse(createTemplate(resourceId)).asPromise();
                case SCHEMA:
                    return newActionResponse(createSchema(context, resourceId)).asPromise();
                default:
            }
        } catch (ResourceException e) {
            return e.asPromise();
        }
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> createInstance(Context context, CreateRequest request) {

        final JsonValue jVal = request.getContent();
        JsonValue idJson = jVal.get(ResourceResponse.FIELD_CONTENT_ID);
        if (idJson == null) {
            return new BadRequestException().asPromise();
        }
        String resourceId = idJson.asString();
        UserServiceHandler handler = handlers.get(resourceId);
        if (handler == null) {
            return new BadRequestException("The service is not supported").asPromise();
        }

        final String realm = realmFor(context);
        String userName = contextHelper.getUserId(context);
        AMIdentity user = getIdentity(userName, realm);
        if (user == null) {
            return new NotFoundException("Resource not found").asPromise();
        }
        if (UserUtils.isDsameUser(user) || UserUtils.isURLAccessAgent(user)) {
            return new ForbiddenException("Request is forbidden for this user").asPromise();
        }
        if (UserUtils.isAmAdminUser(user) || UserUtils.isAnonymousUser(user)) {
            return new BadRequestException("Cannot create services for this user").asPromise();
        }

        try {
            JsonValue result = handler.createService(user, realm, jVal, getLocale(context));
            return newResultPromise(newResourceResponse(resourceId,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("UserServiceResource.createInstance() :: Cannot CREATE {}'s service {}",
                    userName, resourceId, e);
        } catch (IdRepoException e) {
            logger.error("UserServiceResource.createInstance() :: Cannot CREATE {}'s service {}",
                    userName, resourceId, e);
        } catch (ResourceException e) {
            logger.error("UserServiceResource.createInstance() :: Cannot CREATE {}'s service {}",
                    userName, resourceId, e);
            return e.asPromise();
        }
        return new InternalServerErrorException("Unable to create service").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context, String resourceId,
            DeleteRequest request) {
        UserServiceHandler handler = handlers.get(resourceId);
        if (handler == null) {
            return new BadRequestException("The service is not supported").asPromise();
        }

        final String realm = realmFor(context);
        String userName = contextHelper.getUserId(context);
        AMIdentity user = getIdentity(userName, realm);
        if (user == null) {
            return new NotFoundException("Resource not found").asPromise();
        }
        if (UserUtils.isDsameUser(user) || UserUtils.isURLAccessAgent(user)) {
            return new ForbiddenException("Request is forbidden for this user").asPromise();
        }
        if (UserUtils.isAmAdminUser(user) || UserUtils.isAnonymousUser(user)) {
            return new BadRequestException("Cannot delete services for this user").asPromise();
        }

        try {
            JsonValue result = handler.deleteService(user, realm);
            return newResultPromise(newResourceResponse(resourceId, "0", result));
        } catch (SSOException e) {
            logger.error("UserServiceResource.deleteInstance() :: Cannot DELETE {}'s service {}",
                    userName, resourceId, e);
        } catch (IdRepoException e) {
            logger.error("UserServiceResource.deleteInstance() :: Cannot DELETE {}'s service {}",
                    userName, resourceId, e);
        } catch (ResourceException e) {
            logger.error("UserServiceResource.deleteInstance() :: Cannot DELETE {}'s service {}",
                    userName, resourceId, e);
            return e.asPromise();
        }
        return new InternalServerErrorException("Unable to delete service").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context context, String resourceId,
            PatchRequest request) {
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, String resourceId,
            ReadRequest request) {
        UserServiceHandler handler = handlers.get(resourceId);
        if (handler == null) {
            return new BadRequestException("The service is not supported").asPromise();
        }

        final String realm = realmFor(context);
        String userName = contextHelper.getUserId(context);
        AMIdentity user = getIdentity(userName, realm);
        if (user == null) {
            return new NotFoundException("Resource not found").asPromise();
        }
        if (UserUtils.isDsameUser(user) || UserUtils.isURLAccessAgent(user)) {
            return new ForbiddenException("Request is forbidden for this user").asPromise();
        }
        if (UserUtils.isAmAdminUser(user) || UserUtils.isAnonymousUser(user)) {
            return new BadRequestException("Cannot read services for this user").asPromise();
        }

        try {
            JsonValue result = handler.readService(user, realm, getLocale(context));
            return newResultPromise(newResourceResponse(resourceId,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("UserServiceResource.readInstance() :: Cannot READ {}'s service {}",
                    userName, resourceId, e);
        } catch (IdRepoException e) {
            logger.error("UserServiceResource.readInstance() :: Cannot READ {}'s service {}",
                    userName, resourceId, e);
        } catch (ResourceException e) {
            logger.error("UserServiceResource.readInstance() :: Cannot READ {}'s service {}",
                    userName, resourceId, e);
            return e.asPromise();
        }
        return new InternalServerErrorException("Unable to read service").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, String resourceId,
            UpdateRequest request) {
        UserServiceHandler handler = handlers.get(resourceId);
        if (handler == null) {
            return new BadRequestException("The service is not supported").asPromise();
        }

        final String realm = realmFor(context);
        String userName = contextHelper.getUserId(context);
        AMIdentity user = getIdentity(userName, realm);
        if (user == null) {
            return new NotFoundException("Resource not found").asPromise();
        }
        if (UserUtils.isDsameUser(user) || UserUtils.isURLAccessAgent(user)) {
            return new ForbiddenException("Request is forbidden for this user").asPromise();
        }
        if (UserUtils.isAmAdminUser(user) || UserUtils.isAnonymousUser(user)) {
            return new BadRequestException("Cannot update services for this user").asPromise();
        }

        try {
            final JsonValue jVal = request.getContent();
            JsonValue result = handler.updateService(user, realm, jVal, getLocale(context));
            return newResultPromise(newResourceResponse(resourceId,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("UserServiceResource.updateInstance() :: Cannot UPDATE {}'s service {}",
                    userName, resourceId, e);
        } catch (IdRepoException e) {
            logger.error("UserServiceResource.updateInstance() :: Cannot UPDATE {}'s service {}",
                    userName, resourceId, e);
        } catch (ResourceException e) {
            logger.error("UserServiceResource.updateInstance() :: Cannot UPDATE {}'s service {}",
                    userName, resourceId, e);
            return e.asPromise();
        }
        return new InternalServerErrorException("Unable to update service").asPromise();
    }

    private JsonValue getAllTypes(Context context) {
        Locale locale = getLocale(context);
        Set<String> services = getAllServiceForUser();
        JsonValue result = getTypes(services, locale);
        return json(object(field(RESULT, result.getObject())));
    }

    private JsonValue getCreatableTypes(Context context, AMIdentity user) throws ResourceException {
        Locale locale = getLocale(context);

        try {
            Set<String> services = getAllServiceForUser();
            Set<String> assignable = user.getAssignableServices();
            services.retainAll(assignable);
            JsonValue result = getTypes(services, locale);
            return json(object(field(RESULT, result.getObject())));
        } catch (SSOException e) {
            logger.error("UserServiceResource.getCreatableTypes() :: Cannot READ {}'s services",
                    user.getName(), e);
        } catch (IdRepoException e) {
            logger.error("UserServiceResource.getCreatableTypes() :: Cannot READ {}'s services",
                    user.getName(), e);
        }
        throw new InternalServerErrorException("Unable to read creatable services");
    }

    private JsonValue getNextDescendents(Context context, AMIdentity user, String realm) throws ResourceException {
        JsonValue result = json(object(field(RESULT, array())));
        Locale locale = getLocale(context);

        try {
            for (UserServiceHandler handler : handlers.values()) {
                try {
                    JsonValue serviceResult = handler.readService(user, realm, locale);
                    result.get(RESULT).add(serviceResult.getObject());
                } catch (BadRequestException be) {
                    // Do Nothing
                }
            }
            return result;
        } catch (SSOException e) {
            logger.error("UserServiceResource.getNextDescendents() :: Cannot READ {}'s services",
                    user.getName(), e);
        } catch (IdRepoException e) {
            logger.error("UserServiceResource.getNextDescendents() :: Cannot READ {}'s services",
                    user.getName(), e);
        }
        throw new InternalServerErrorException("Unable to read services");
    }

    private JsonValue createSchema(Context context, String resourceId) throws ResourceException {
        UserServiceHandler handler = handlers.get(resourceId);
        if (handler == null) {
            throw new BadRequestException("The service is not supported");
        }
        return handler.createSchema(getLocale(context), realmFor(context));
    }

    private JsonValue createTemplate(String resourceId) throws ResourceException {
        UserServiceHandler handler = handlers.get(resourceId);
        if (handler == null) {
            throw new BadRequestException("The service is not supported");
        }
        return handler.createTemplate();
    }

    private Map<String, UserServiceHandler> createServiceHandlers(AMResourceBundleCache resourceBundleCache) {
        Map<String, UserServiceHandler> result = new HashMap<String, UserServiceHandler>();
        try {
            ServiceManager sm = new ServiceManager(RestUtils.getToken());
            Map sMap = sm.getServiceNamesAndOCs(IdType.USER.getName());
            Set<String> services = sMap.keySet();

            // The following services are not supported.
            // * User Service
            // * SAML Service
            // * Authentication Configuration Service
            // * Discovery Service
            // * Liberty Personal Profile Service
            services.remove(Constants.SVC_NAME_USER);
            services.remove(Constants.SVC_NAME_AUTH_CONFIG);
            services.remove(Constants.SVC_NAME_SAML);
            services.remove("sunIdentityServerDiscoveryService");
            services.remove("sunIdentityServerLibertyPPService");

            for (String service : services) {
                UserServiceHandler handler = new UserServiceHandler(service, resourceBundleCache);
                result.put(handler.getResourceName(), handler);
            }
        } catch (SSOException e) {
            logger.error(
                    "UserServiceResource.createServiceHandlers() :: Failed to create service handlers", e);
        } catch (SMSException e) {
            logger.error(
                    "UserServiceResource.createServiceHandlers() :: Failed to create service handlers", e);
        }
        return result;
    }

    private Set<String> getAllServiceForUser() {
        Set<String> result = new HashSet<String>();
        for (UserServiceHandler handler : handlers.values()) {
            result.add(handler.getServiceName());
        }
        return result;
    }

    private JsonValue getTypes(Set<String> services, Locale locale) {
        JsonValue result = json(array());
        for (String service : services) {
            for (UserServiceHandler handler : handlers.values()) {
                if (handler.getServiceName().equals(service)) {
                    result.add(handler.getTypeValue(locale));
                    break;
                }
            }
        }
        return result;
    }

    private Locale getLocale(Context context) {
        return context.asContext(LocaleContext.class).getLocale();
    }

    private AMIdentity getIdentity(String userName, String realm) {
        return IdUtils.getIdentity(userName, realm);
    }
}
