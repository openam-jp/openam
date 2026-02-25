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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.core.rest.IdentityRestUtils.getIdentityServicesAttributes;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.ARRAY_TYPE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.DESCRIPTION;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.EXAMPLE_VALUE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.ITEMS;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.OBJECT_TYPE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.PROPERTIES;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.PROPERTY_ORDER;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.REQUIRED;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.STRING_TYPE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.TITLE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.TYPE;
import static org.forgerock.openam.rest.RestConstants.SCHEMA;
import static org.forgerock.openam.rest.RestUtils.realmFor;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;

import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.CollectionResourceProvider;
import org.forgerock.json.resource.ConflictException;
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
import org.forgerock.openam.forgerockrest.utils.PrincipalRestUtils;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.openam.rest.resource.LocaleContext;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.CrestQuery;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.query.QueryFilter;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoDuplicateObjectException;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.idsvcs.IdentityDetails;
import com.sun.identity.idsvcs.ListWrapper;
import com.sun.identity.idsvcs.opensso.IdentityServicesImpl;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;

/**
 * REST resource for Group Management.
 */
public class GroupResource implements CollectionResourceProvider {

    private static final Debug logger = Debug.getInstance("frRest");
    private static final String I18N_FILE = "schemaI18n";
    private static final String I18N_PREFIX = "group.";
    private static final String PROPERTY_NAME = "uniqueMember";

    private final IdentityServicesImpl identityServices;

    @Inject
    public GroupResource(IdentityServicesImpl identityServices) {
        this.identityServices = identityServices;
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionCollection(Context context,
            ActionRequest request) {
        switch (request.getAction()) {
            case SCHEMA:
                return newActionResponse(createSchema(context)).asPromise();
            default:
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
            final JsonValue jVal = request.getContent();
            resourceId = jVal.get(ResourceResponse.FIELD_CONTENT_ID).asString();
            Set<AMIdentity> members = getMemberFromJson(jVal, realm);

            final AMIdentityRepository amIdRepo = IdUtils.getAMIdentityRepository(DNMapper.orgNameToDN(realm));
            AMIdentity groupIdentity = amIdRepo.createIdentity(IdType.GROUP, resourceId, new HashMap<>());
            if (members != null) {
                for (AMIdentity member : members) {
                    groupIdentity.addMember(member);
                }
            }

            JsonValue content = amIdentityToJsonValue(groupIdentity);

            ResourceResponse resource = newResourceResponse(resourceId,
                    String.valueOf(content.getObject().hashCode()), content);
            return newResultPromise(resource);
        } catch (SSOException e) {
            logger.error("GroupResource.createInstance() :: Cannot CREATE resourceId={}", resourceId, e);
            return new ForbiddenException(e).asPromise();
        } catch (IdRepoDuplicateObjectException e) {
            logger.error("GroupResource.createInstance() :: Cannot CREATE resourceId={}", resourceId, e);
            return new ConflictException("Resource already exists").asPromise();
        } catch (IdRepoException e) {
            logger.error("GroupResource.createInstance() :: Cannot CREATE resourceId={}", resourceId, e);
            return new BadRequestException().asPromise();
        } catch (BadRequestException e) {
            logger.error("GroupResource.createInstance() :: Cannot CREATE resourceId={}", resourceId, e);
            return e.asPromise();
        } catch (final Exception e) {
            logger.error("GroupResource.createInstance() :: Cannot CREATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to create group").asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context,
            String resourceId, DeleteRequest request) {
        final String realm = realmFor(context);
        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>(1));

        try {
            AMIdentity groupIdentity = IdUtils.getGroupIdentity(resourceId, realm);
            if (groupIdentity == null) {
                return new NotFoundException("Resource not found").asPromise();
            }

            final AMIdentityRepository amIdRepo = IdUtils.getAMIdentityRepository(DNMapper.orgNameToDN(realm));
            amIdRepo.deleteIdentities(CollectionUtils.asSet(groupIdentity));

            result.put("success", true);
            ResourceResponse resource = newResourceResponse(resourceId, "0", result);
            return newResultPromise(resource);
        } catch (SSOException e) {
            logger.error("GroupResource.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to read group").asPromise();
        } catch (IdRepoException e) {
            logger.error("GroupResource.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            return new BadRequestException("Unable to read group").asPromise();
        } catch (final Exception e) {
            logger.error("GroupResource.deleteInstance() :: Cannot DELETE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to delete group").asPromise();
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
            List<IdentityDetails> groupDetails = null;

            // If the user specified _queryFilter, then (convert and) use that, otherwise look for _queryID
            // and if that isn't there either, pretend the user gave a _queryID of "*"
            //
            QueryFilter<JsonPointer> queryFilter = request.getQueryFilter();
            if (queryFilter != null) {
                CrestQuery crestQuery = new CrestQuery(queryFilter);
                groupDetails = identityServices.searchIdentityDetails(crestQuery,
                        getIdentityServicesAttributes(realm, IdType.GROUP.getName()),
                        admin);
            } else {
                String queryId = request.getQueryId();
                if (queryId == null || queryId.isEmpty()) {
                    queryId = "*";
                }
                CrestQuery crestQuery = new CrestQuery(queryId);
                groupDetails = identityServices.searchIdentityDetails(crestQuery,
                        getIdentityServicesAttributes(realm, IdType.GROUP.getName()),
                        admin);
            }

            String principalName = PrincipalRestUtils.getPrincipalNameFromServerContext(context);
            logger.message("GroupResource.queryCollection() :: QUERY performed on realm "
                    + realm
                    + " by "
                    + principalName);

            List<ResourceResponse> results = new ArrayList<>();
            for (IdentityDetails groupDetail : groupDetails) {
                results.add(newResourceResponse(groupDetail.getName(),
                        "0",
                        identityDetailsToJsonValueForQuery(groupDetail)));
            }

            return QueryResponsePresentation.perform(handler, request, results);
        } catch (ResourceException resourceException) {
            logger.warning("GroupResource.queryCollection() caught ResourceException", resourceException);
            return resourceException.asPromise();
        } catch (Exception exception) {
            logger.error("GroupResource.queryCollection() caught exception", exception);
            return new InternalServerErrorException("Unable to query groups").asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context,
            String resourceId, ReadRequest request) {
        final String realm = realmFor(context);

        try {
            AMIdentity groupIdentity = IdUtils.getGroupIdentity(resourceId, realm);
            if (groupIdentity == null) {
                return new NotFoundException("Resource not found").asPromise();
            }

            JsonValue content = amIdentityToJsonValue(groupIdentity);
            return newResultPromise(newResourceResponse(resourceId,
                    String.valueOf(content.getObject().hashCode()), content));
        } catch (SSOException e) {
            logger.error("GroupResource.readInstance() :: Cannot READ resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to read group").asPromise();
        } catch (IdRepoException e) {
            logger.error("GroupResource.readInstance() :: Cannot READ resourceId={}", resourceId, e);
            return new BadRequestException("Unable to read group").asPromise();
        } catch (final Exception e) {
            logger.error("GroupResource.readInstance() :: Cannot READ resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to read group").asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context,
            String resourceId, UpdateRequest request) {
        final String realm = realmFor(context);

        try {
            final JsonValue jVal = request.getContent();
            Set<AMIdentity> newMembers = getMemberFromJson(jVal, realm);

            AMIdentity groupIdentity = IdUtils.getGroupIdentity(resourceId, realm);
            if (groupIdentity == null) {
                return new NotFoundException("Resource not found").asPromise();
            }

            if (newMembers != null) {
                Set<AMIdentity> currentMembers = groupIdentity.getMembers(IdType.USER);

                Set<AMIdentity> toAdd = new HashSet<>(newMembers);
                toAdd.removeAll(currentMembers);
                Set<AMIdentity> toRemove = new HashSet<>(currentMembers);
                toRemove.removeAll(newMembers);

                for (AMIdentity user : toAdd) {
                    groupIdentity.addMember(user);
                }
                for (AMIdentity user : toRemove) {
                    groupIdentity.removeMember(user);
                }
            }

            JsonValue content = amIdentityToJsonValue(groupIdentity);

            ResourceResponse resource = newResourceResponse(resourceId,
                    String.valueOf(content.getObject().hashCode()), content);
            return newResultPromise(resource);
        } catch (SSOException e) {
            logger.error("GroupResource.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new ForbiddenException(e).asPromise();
        } catch (IdRepoException e) {
            logger.error("GroupResource.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new BadRequestException().asPromise();
        } catch (BadRequestException e) {
            logger.error("GroupResource.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return e.asPromise();
        } catch (final Exception e) {
            logger.error("GroupResource.updateInstance() :: Cannot UPDATE resourceId={}", resourceId, e);
            return new InternalServerErrorException("Unable to update group").asPromise();
        }
    }

    private JsonValue createSchema(Context context) {
        ResourceBundle schemaI18n = ResourceBundle.getBundle(I18N_FILE, getLocale(context));
        JsonValue result = json(object(field(TYPE, OBJECT_TYPE)));
        String path = "/" + PROPERTIES + "/" + PROPERTY_NAME;
        String prefix = I18N_PREFIX + PROPERTY_NAME + ".";
        result.addPermissive(new JsonPointer(path+ "/" + TITLE),
                schemaI18n.getString(prefix + TITLE));
        result.addPermissive(new JsonPointer(path + "/" + DESCRIPTION),
                schemaI18n.getString(prefix + DESCRIPTION));
        result.addPermissive(new JsonPointer(path + "/" + PROPERTY_ORDER), 100);
        result.addPermissive(new JsonPointer(path + "/" + REQUIRED), false);
        result.addPermissive(new JsonPointer(path + "/" + ITEMS),
                object(field(TYPE, STRING_TYPE)));
        result.addPermissive(new JsonPointer(path + "/" + TYPE), ARRAY_TYPE);
        result.addPermissive(new JsonPointer(path + "/" + EXAMPLE_VALUE), "");
        return result;
    }

    protected JsonValue identityDetailsToJsonValueForQuery(IdentityDetails dtls) {
        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>());

        result.put(ResourceResponse.FIELD_CONTENT_ID, dtls.getName());

        Set<String> memberNames = new HashSet<>();
        ListWrapper list = dtls.getMemberList();
        if (list != null) {
            memberNames = new HashSet<>(Arrays.asList(list.getElements()));
        }
        if (!memberNames.isEmpty()) {
            result.put(PROPERTY_NAME, memberNames);
        }

        return result;
    }

    private AMIdentity getUserIdentity(String userName, String realm) {
        // return null if user is not found
        return IdUtils.getIdentity(userName, realm);
    }

    private JsonValue amIdentityToJsonValue(AMIdentity groupIdentity)
            throws SSOException, IdRepoException {
        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>());

        result.put(ResourceResponse.FIELD_CONTENT_ID, groupIdentity.getName());

        Set<AMIdentity> members = groupIdentity.getMembers(IdType.USER);
        Set<String> memberNames = new HashSet<>();
        for (AMIdentity member : members) {
            memberNames.add(member.getName());
        }
        if (!memberNames.isEmpty()) {
            result.put(PROPERTY_NAME, memberNames);
        }

        return result;
    }

    private Set<AMIdentity> getMemberFromJson(JsonValue jsonValue, String realm)
            throws BadRequestException {
        Set<AMIdentity> result = null;

        for (String jsonKey : jsonValue.keys()) {

            // Ignore _id field used to name resource when creating
            if (ResourceResponse.FIELD_CONTENT_ID.equals(jsonKey)) {
                continue;
            }

            if (PROPERTY_NAME.equals(jsonKey)) {
                result = new HashSet<>();
                JsonValue property = jsonValue.get(PROPERTY_NAME);
                if (property.isList()) {
                    for (Object obj : property.asList()) {
                        if (!(obj instanceof String)) {
                            throw new BadRequestException("Invalid attribute value syntax");
                        }
                        String memberName = (String) obj;
                        AMIdentity user = getUserIdentity(memberName, realm);
                        if (user == null) {
                            throw new BadRequestException("The user specified as member is not found");
                        }
                        result.add(user);
                    }
                } else {
                    throw new BadRequestException("Invalid attribute value syntax");
                }
            } else {
                throw new BadRequestException("Invalid attribute specified");
            }
        }

        return result;
    }

    private Locale getLocale(Context context) {
        return context.asContext(LocaleContext.class).getLocale();
    }
}
