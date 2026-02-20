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

import static com.sun.identity.idsvcs.opensso.IdentityServicesImpl.asAttributeArray;
import static com.sun.identity.idsvcs.opensso.IdentityServicesImpl.asMap;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.core.rest.IdentityRestUtils.getIdentityServicesAttributes;
import static org.forgerock.openam.rest.RestConstants.*;
import static org.forgerock.openam.rest.RestUtils.realmFor;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.forgerock.json.JsonPointer;
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
import org.forgerock.json.resource.PermanentException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.core.rest.IdentityRestUtils;
import org.forgerock.openam.core.rest.sms.SmsJsonConverter;
import org.forgerock.openam.core.rest.sms.SmsJsonSchema;
import org.forgerock.openam.forgerockrest.utils.PrincipalRestUtils;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.openam.rest.resource.LocaleContext;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.openam.utils.CrestQuery;
import org.forgerock.services.context.Context;
import org.forgerock.util.AsyncFunction;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.query.QueryFilter;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.common.CaseInsensitiveHashMap;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.idsvcs.AccessDenied;
import com.sun.identity.idsvcs.Attribute;
import com.sun.identity.idsvcs.GeneralFailure;
import com.sun.identity.idsvcs.IdentityDetails;
import com.sun.identity.idsvcs.NeedMoreCredentials;
import com.sun.identity.idsvcs.ObjectNotFound;
import com.sun.identity.idsvcs.TokenExpired;
import com.sun.identity.idsvcs.opensso.GeneralAccessDeniedError;
import com.sun.identity.idsvcs.opensso.IdentityServicesImpl;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceSchema;
import com.sun.identity.sm.ServiceSchemaManager;

import jp.co.osstech.openam.core.rest.sms.AttributeSchemaFilter;

/**
 * REST resource for User Management.
 */
public class UserResource implements CollectionResourceProvider {

    private static Debug logger = Debug.getInstance("frRest");

    private final IdentityServicesImpl identityServices;
    private final SmsJsonConverter converter;
    private final ServiceSchema schema;
    private final AttributeSchemaFilter filter;

    @Inject
    public UserResource(IdentityServicesImpl identityServices) {
        this.identityServices = identityServices;

        ServiceSchema userSchema = null;
        try {
            String serviceName = IdUtils.getServiceName(IdType.USER);
            SSOToken admin = RestUtils.getToken();
            ServiceSchemaManager svcSchemaMgr = new ServiceSchemaManager(serviceName, admin);
            userSchema = svcSchemaMgr.getSchema(IdType.USER.getName());
        } catch (SMSException e) {
            logger.error("UserResource :: Unable to get the service schema", e);
        } catch (SSOException e) {
            logger.error("UserResource :: Unable to get the service schema", e);
        }
        this.schema = userSchema;
        this.filter = new EntitiesAttributeSchemaFilter();
        this.converter = new UserJsonConverter(schema, filter);
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionCollection(Context context,
            ActionRequest request) {
        try {
            switch (request.getAction()) {
                case TEMPLATE:
                    return newActionResponse(createTemplate()).asPromise();
                case SCHEMA:
                    return newActionResponse(createSchema(context)).asPromise();
                default:
            }
        } catch (ResourceException re) {
            return re.asPromise();
        }
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionInstance(Context context,
            String resourceId, ActionRequest request) {
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> createInstance(final Context context,
            CreateRequest request) {
        final String realm = realmFor(context);
        String resourceId = null;

        try {
            SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();

            final JsonValue jVal = request.getContent();

            IdentityDetails identity = jsonValueToIdentityDetails(
                    jVal.get(ResourceResponse.FIELD_CONTENT_ID).asString(), jVal, realm);
            resourceId = identity.getName();
            return attemptResourceCreation(realm, admin, identity, resourceId)
                    .thenAsync(new AsyncFunction<IdentityDetails, ResourceResponse, ResourceException>() {
                        @Override
                        public Promise<ResourceResponse, ResourceException> apply(IdentityDetails dtls) {
                            if (dtls != null) {
                                String id = dtls.getName();
                                String principalName = PrincipalRestUtils.getPrincipalNameFromServerContext(context);
                                logger.message("UserResource.createInstance() :: CREATE of resourceId={} in realm={} "
                                        + "performed by principalName={}", id, realm, principalName);

                                JsonValue content = identityDetailsToJsonValue(dtls);
                                ResourceResponse resource = newResourceResponse(id,
                                        String.valueOf(content.getObject().hashCode()), content);
                                return newResultPromise(resource);
                            } else {
                                logger.error("UserResource.createInstance() :: Identity not found");
                                return new NotFoundException("Resource not found").asPromise();
                            }
                        }
                    });
        } catch (BadRequestException bre){
            logger.error("UserResource.createInstance() :: Cannot CREATE resourceId={}", resourceId, bre);
            return bre.asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context,
            String resourceId, DeleteRequest request) {
        final String realm = realmFor(context);

        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>(1));
        ResourceResponse resource;

        try {
            SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();

            // read to see if resource is available to user
            IdentityDetails dtls = identityServices.read(resourceId,
                    getIdentityServicesAttributes(realm, IdType.USER.getName()), admin);

            if (isAmAdminUser(dtls, admin)) {
                return new BadRequestException("Cannot delete this user").asPromise();
            }

            // delete the resource
            identityServices.delete(dtls, admin);
            String principalName = PrincipalRestUtils.getPrincipalNameFromServerContext(context);
            logger.message("UserResource.deleteInstance() :: DELETE of resourceId={} in realm={} performed by " +
                    "principalName={}", resourceId, realm, principalName);

            result.put("success", true);
            resource = newResourceResponse(resourceId, "0", result);
            return newResultPromise(resource);

        } catch (final NeedMoreCredentials ex) {
            logger.error("UserResource.deleteInstance() :: Cannot DELETE resourceId={} : User does not have enough" +
                    " privileges.", resourceId, ex);
            return new ForbiddenException(resourceId, ex).asPromise();
        } catch (final ObjectNotFound notFound) {
            logger.error("UserResource.deleteInstance() :: Cannot DELETE {} : Resource cannot be found.",
                    resourceId, notFound);
            return new NotFoundException("Resource not found", notFound).asPromise();
        } catch (final TokenExpired tokenExpired) {
            logger.error("UserResource.deleteInstance() :: Cannot DELETE resourceId={} : Unauthorized",
                    resourceId, tokenExpired);
            return new PermanentException(401, "Unauthorized", null).asPromise();
        } catch (final AccessDenied accessDenied) {
            logger.error("UserResource.deleteInstance() :: Cannot DELETE resourceId={} : Access denied" ,
                    resourceId, accessDenied);
            return new ForbiddenException(accessDenied).asPromise();
        } catch (final GeneralFailure generalFailure) {
            logger.error("UserResource.deleteInstance() :: Cannot DELETE resourceId={} : general failure",
                    resourceId, generalFailure);
            return new BadRequestException(generalFailure.getMessage(), generalFailure).asPromise();
        } catch (ForbiddenException ex) {
            logger.warning("UserResource.deleteInstance() :: Cannot DELETE resourceId={}: User does not have " +
                    "enough privileges.", resourceId, ex);
            return new ForbiddenException(resourceId, ex).asPromise();
        } catch (NotFoundException notFound) {
            logger.warning("UserResource.deleteInstance() :: Cannot DELETE resourceId={} : Resource cannot be found",
                    resourceId, notFound);
            return new NotFoundException("Resource not found", notFound).asPromise();
        } catch (ResourceException re) {
            logger.warning("UserResource.deleteInstance() :: Cannot DELETE resourceId={} : resource failure",
                    resourceId, re);
            result.put("success", "false");
            resource = newResourceResponse(resourceId, "0", result);
            return newResultPromise(resource);
        } catch (Exception e) {
            logger.error("UserResource.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            result.put("success", "false");
            resource = newResourceResponse(resourceId, "0", result);
            return newResultPromise(resource);
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context context,
            String resourceId, PatchRequest request) {
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<QueryResponse, ResourceException> queryCollection(Context context,
            QueryRequest request, QueryResourceHandler handler) {
        final String realm = realmFor(context);

        try {
            SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            List<IdentityDetails> userDetails = null;

            // If the user specified _queryFilter, then (convert and) use that, otherwise look for _queryID
            // and if that isn't there either, pretend the user gave a _queryID of "*"
            //
            QueryFilter<JsonPointer> queryFilter = request.getQueryFilter();
            if (queryFilter != null) {
                CrestQuery crestQuery = new CrestQuery(queryFilter);
                userDetails = identityServices.searchIdentityDetails(crestQuery,
                        getIdentityServicesAttributes(realm, IdType.USER.getName()),
                        admin);
            } else {
                String queryId = request.getQueryId();
                if (queryId == null || queryId.isEmpty()) {
                    queryId = "*";
                }
                CrestQuery crestQuery = new CrestQuery(queryId);
                userDetails = identityServices.searchIdentityDetails(crestQuery,
                        getIdentityServicesAttributes(realm, IdType.USER.getName()),
                        admin);
            }

            String principalName = PrincipalRestUtils.getPrincipalNameFromServerContext(context);
            logger.message("UserResource.queryCollection() :: QUERY performed on realm "
                    + realm
                    + " by "
                    + principalName);

            List<ResourceResponse> results = new ArrayList<>();
            for (IdentityDetails userDetail : userDetails) {
                results.add(newResourceResponse(userDetail.getName(),
                        "0",
                        identityDetailsToJsonValue(userDetail)));
            }

            return QueryResponsePresentation.perform(handler, request, results);
        } catch (ResourceException resourceException) {
            logger.warning("UserResource.queryCollection() caught ResourceException", resourceException);
            return resourceException.asPromise();
        } catch (Exception exception) {
            logger.error("UserResource.queryCollection() caught exception", exception);
            return new InternalServerErrorException(exception.getMessage(), exception).asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context,
            String resourceId, ReadRequest request) {
        final String realm = realmFor(context);

        try {
            SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            IdentityDetails dtls = identityServices.read(resourceId, getIdentityServicesAttributes(realm,
                    IdType.USER.getName()), admin);
            String principalName = PrincipalRestUtils.getPrincipalNameFromServerContext(context);
            if (logger.messageEnabled()) {
                logger.message("UserResource.readInstance() :: READ of resourceId={} in realm={} performed by " +
                        "principalName={}", resourceId, realm, principalName);
            }
            JsonValue content = identityDetailsToJsonValue(dtls);
            return newResultPromise(newResourceResponse(resourceId,
                    String.valueOf(content.getObject().hashCode()), content));
        } catch (final NeedMoreCredentials needMoreCredentials) {
            logger.error("UserResource.readInstance() :: Cannot READ resourceId={} : User does not have enough " +
                            "privileges.", resourceId,  needMoreCredentials);
            return new ForbiddenException("User does not have enough privileges.", needMoreCredentials).asPromise();
        } catch (final ObjectNotFound objectNotFound) {
            logger.error("UserResource.readInstance() :: Cannot READ resourceId={} : Resource cannot be found.",
                    resourceId, objectNotFound);
            return new NotFoundException("Resource not found", objectNotFound).asPromise();
        } catch (final TokenExpired tokenExpired) {
            logger.error("UserResource.readInstance() :: Cannot READ resourceId={} : Unauthorized", resourceId,
                    tokenExpired);
            return new PermanentException(401, "Unauthorized", null).asPromise();
        } catch (final AccessDenied accessDenied) {
            logger.error("UserResource.readInstance() :: Cannot READ resourceId={} : Access denied",
                    resourceId, accessDenied);
            return new ForbiddenException(accessDenied.getMessage(), accessDenied).asPromise();
        } catch (final GeneralFailure generalFailure) {
            logger.error("UserResource.readInstance() :: Cannot READ resourceId={}", resourceId, generalFailure);
            return new BadRequestException(generalFailure.getMessage(), generalFailure).asPromise();
        } catch (final Exception e) {
            logger.error("UserResource.readInstance() :: Cannot READ resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to read user").asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context,
            String resourceId, UpdateRequest request) {
        final String realm = realmFor(context);

        final JsonValue jVal = request.getContent();
        try {
            SSOToken token = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            // Retrieve details about user to be updated
            IdentityDetails dtls = identityServices.read(resourceId,
                    getIdentityServicesAttributes(realm, IdType.USER.getName()), token);

            IdentityDetails newDtls = jsonValueToIdentityDetails(resourceId, jVal, realm);

            if (newDtls.getAttributes() == null || newDtls.getAttributes().length < 1) {
                throw new BadRequestException("Illegal arguments: One or more required arguments is null or empty");
            }

            newDtls.setName(resourceId);

            // update resource with new details
            identityServices.update(newDtls, token);
            String principalName = PrincipalRestUtils.getPrincipalNameFromServerContext(context);
            logger.message("UserResource.updateInstance() :: UPDATE of resourceId={} in realm={} performed " +
                    "by principalName={}", resourceId, realm, principalName);
            // read updated identity back to client
            IdentityDetails checkIdent = identityServices.read(dtls.getName(),
                    getIdentityServicesAttributes(realm, IdType.USER.getName()), token);
            JsonValue content = identityDetailsToJsonValue(checkIdent);
            return newResultPromise(newResourceResponse(resourceId,
                    String.valueOf(content.getObject().hashCode()), content));
        } catch (final ObjectNotFound onf) {
            logger.error("UserResource.updateInstance() :: Cannot UPDATE resourceId={} : Could not find the " +
                    "resource", resourceId, onf);
            return new NotFoundException("Resource not found", onf).asPromise();
        } catch (final NeedMoreCredentials needMoreCredentials) {
            logger.error("UserResource.updateInstance() :: Cannot UPDATE resourceId={} : Token is not authorized",
                    resourceId, needMoreCredentials);
            return new ForbiddenException("Token is not authorized", needMoreCredentials).asPromise();
        } catch (final TokenExpired tokenExpired) {
            logger.error("UserResource.updateInstance() :: Cannot UPDATE resourceId={} : Unauthorized",
                    resourceId, tokenExpired);
            return new PermanentException(401, "Unauthorized", null).asPromise();
        } catch (final AccessDenied accessDenied) {
            logger.error("UserResource.updateInstance() :: Cannot UPDATE resourceId={} : Access denied",
                    resourceId, accessDenied);
            return new ForbiddenException(accessDenied.getMessage(), accessDenied).asPromise();
        } catch (final GeneralFailure generalFailure) {
            logger.error("UserResource.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, generalFailure);
            return new BadRequestException(generalFailure.getMessage(), generalFailure).asPromise();
        } catch (BadRequestException bre){
            logger.error("UserResource.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, bre);
            return bre.asPromise();
        } catch (NotFoundException e) {
            logger.warning("UserResource.updateInstance() :: Cannot UPDATE resourceId={} : Could not find the " +
                    "resource", resourceId, e);
            return new NotFoundException("Resource not found", e).asPromise();
        } catch (ResourceException re) {
            logger.warning("UserResource.updateInstance() :: Cannot UPDATE resourceId={} ", resourceId, re);
            return re.asPromise();
        } catch (final Exception e) {
            logger.error("UserResource.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to update user").asPromise();
        }
    }

    private JsonValue identityDetailsToJsonValue(IdentityDetails dtls) {
        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>());

        result.put(ResourceResponse.FIELD_CONTENT_ID, dtls.getName());
        Map<String, Set<String>> userAttrs = new CaseInsensitiveHashMap(asMap(dtls.getAttributes()));
        Map<String, Set<String>> targetAttrs = new HashMap<>();

        for (AttributeSchema as : schema.getAttributeSchemas()) {
            String attrName = as.getName();
            if (filter.isTarget(as) && userAttrs.containsKey(attrName)
                    && !IdentityRestUtils.isPasswordAttribute(attrName)) {
                targetAttrs.put(attrName, userAttrs.get(attrName));
            }
        }

        return converter.toJson(targetAttrs, false, result);
    }

    private IdentityDetails jsonValueToIdentityDetails(String id, final JsonValue jVal, final String realm)
            throws BadRequestException {

        IdentityDetails identity = new IdentityDetails();

        identity.setName(id);
        identity.setType(IdType.USER.getName());
        identity.setRealm(realm);

        Map<String, Set<String>> targetAttrs = converter.fromJson(realm, jVal);

        identity.setAttributes(asAttributeArray(targetAttrs));

        return identity;
    }

    private Promise<IdentityDetails, ResourceException> attemptResourceCreation(String realm, SSOToken admin,
            IdentityDetails identity, String resourceId) {

        IdentityDetails dtls = null;

        try {
            // Create the resource
            identityServices.create(identity, admin);
            // Read created resource
            dtls = identityServices.read(resourceId,
                    getIdentityServicesAttributes(realm, IdType.USER.getName()), admin);
            if (logger.messageEnabled()) {
                logger.message("UserResource.createInstance() :: Created resourceId={} in realm={} by AdminID={}",
                        resourceId, realm, admin.getTokenID());
            }
        } catch (final ObjectNotFound notFound) {
            logger.error("UserResource.createInstance() :: Cannot CREATE resourceId={} : Resource cannot be found.",
                    resourceId, notFound);
            return new NotFoundException("Resource not found", notFound).asPromise();
        } catch (final TokenExpired tokenExpired) {
            logger.error("UserResource.createInstance() :: Cannot CREATE resourceId={} : Unauthorized", resourceId,
                    tokenExpired);
            return new PermanentException(401, "Unauthorized", null).asPromise();
        } catch (final NeedMoreCredentials needMoreCredentials) {
            logger.error("UserResource.createInstance() :: Cannot CREATE resourceId={} : Token is not authorized",
                    resourceId, needMoreCredentials);
            return new ForbiddenException("Token is not authorized", needMoreCredentials).asPromise();
        } catch (final GeneralAccessDeniedError accessDenied) {
            logger.error("UserResource.createInstance() :: Cannot CREATE " + accessDenied);
            return new ForbiddenException().asPromise();
        } catch (GeneralFailure generalFailure) {
            logger.error("UserResource.createInstance() :: Cannot CREATE " +
                    generalFailure);
            return new BadRequestException("Resource cannot be created: "
                    + generalFailure.getMessage(), generalFailure).asPromise();
        } catch (AccessDenied accessDenied) {
            logger.error("UserResource.createInstance() :: Cannot CREATE " +
                    accessDenied);
            return new ForbiddenException("Token is not authorized: " + accessDenied.getMessage(), accessDenied)
                    .asPromise();
        } catch (ResourceException re) {
            logger.warning("UserResource.createInstance() :: Cannot CREATE resourceId={}", resourceId, re);
            return re.asPromise();
        } catch (final Exception e) {
            logger.error("UserResource.createInstance() :: Cannot CREATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to create user").asPromise();
        }
        return newResultPromise(dtls);
    }

    private JsonValue createSchema(Context context) throws ResourceException {
        if (schema == null) {
            throw new InternalServerErrorException("Unable to get the service schema");
        }
        JsonValue result = json(object(field("type", "object")));
        SmsJsonSchema.addAttributeSchema(result, "/" + "properties" + "/", schema,
                getLocale(context), realmFor(context), filter);
        return result;
    }

    protected JsonValue createTemplate() throws ResourceException {
        if (schema == null) {
            throw new InternalServerErrorException("Unable to get the service schema");
        }
        Map<String, Set<String>> defaults = schema.getAttributeDefaults();
        for (AttributeSchema as : schema.getAttributeSchemas()) {
            if (filter.isTarget(as)) {
                // The default value of some attributes are non-breaking space. Replace these with null.
                Set<String> values = defaults.get(as.getName());
                if (values.size() == 1 && "\u00a0".equals(values.iterator().next())) {
                    defaults.put(as.getName(), new HashSet<String>(0));
                }
            } else {
                defaults.remove(as.getName());
            }
        }
        return converter.toJson(defaults, false);
    }

    private Locale getLocale(Context context) {
        return context.asContext(LocaleContext.class).getLocale();
    }

    private boolean isAmAdminUser(IdentityDetails dtls, SSOToken admin) {
        String univId;
        Attribute[] attrs = dtls.getAttributes();
        if (attrs == null || attrs.length == 0) {
            return false;
        }
        for (Attribute attr : attrs) {
            if (attr.getName().equals(IdentityRestUtils.UNIVERSAL_ID)) {
                try {
                    AMIdentity amid = new AMIdentity(admin, attr.getValues()[0]);
                    return UserUtils.isAmAdminUser(amid);
                } catch (IdRepoException e) {
                    logger.error("UserResource.isAmAdminUser() :: Unable to identify user", e);
                }
            }
        }
        return false;
    }
}
