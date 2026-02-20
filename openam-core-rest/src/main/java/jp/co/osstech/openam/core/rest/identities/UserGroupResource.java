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

import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.*;
import static org.forgerock.openam.rest.RestConstants.*;
import static org.forgerock.openam.rest.RestUtils.realmFor;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;

import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ForbiddenException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.SingletonResourceProvider;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.openam.rest.resource.LocaleContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;

/**
 * REST resource for User's Group.
 */
public class UserGroupResource implements SingletonResourceProvider {

    private static final String I18N_FILE = "schemaI18n";
    private static final String I18N_PREFIX = "usergroup.groups.";

    private static Debug logger = Debug.getInstance("frRest");

    private final ContextHelper contextHelper;

    @Inject
    public UserGroupResource(ContextHelper helper) {
        this.contextHelper = helper;
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionInstance(Context context, ActionRequest request) {
        switch (request.getAction()) {
            case SCHEMA:
                return newActionResponse(createSchema(context)).asPromise();
            default:
        }
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context context, PatchRequest request) {
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, ReadRequest request) {
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
            JsonValue result = json(object(field(GROUPS, array())));
            return newResultPromise(newResourceResponse(userName,
                    String.valueOf(result.getObject().hashCode()), result));
        }

        try {
            JsonValue result = readGroups(user);
            return newResultPromise(newResourceResponse(userName,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("UserGroupResource.readInstance() :: Cannot READ {}'s groups", userName, e);
            return new InternalServerErrorException("Unable to read groups").asPromise();
        } catch (IdRepoException e) {
            logger.error("UserGroupResource.readInstance() :: Cannot READ {}'s groups", userName, e);
            return new InternalServerErrorException("Unable to read groups").asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, UpdateRequest request) {
        final String realm = realmFor(context);
        String userName = contextHelper.getUserId(context);

        final JsonValue content = request.getContent();
        for (String jsonKey : content.keys()) {
            if (!GROUPS.equals(jsonKey)) {
                return new BadRequestException("Invalid attribute specified").asPromise();
            }
        }
        JsonValue groupsJson = content.get(GROUPS);
        if (groupsJson == null) {
            return new BadRequestException(
                    "'" + GROUPS + "' attribute not set in JSON content.").asPromise();
        }
        Set<String> requestGroups = groupsJson.asSet(String.class);

        AMIdentity user = getIdentity(userName, realm);
        if (user == null) {
            return new NotFoundException("Resource not found").asPromise();
        }
        if (UserUtils.isDsameUser(user) || UserUtils.isURLAccessAgent(user)) {
            // dsameuser & amService-URLAccessAgent
            return new ForbiddenException("Request is forbidden for this user").asPromise();
        }
        if (UserUtils.isAmAdminUser(user) || UserUtils.isAnonymousUser(user)) {
            // amadmin & anonymous
            return new BadRequestException("Cannot update groups for this user").asPromise();
        }

        try {
            Set<AMIdentity> currentGroups = user.getMemberships(IdType.GROUP);
            Set<AMIdentity> newGroups = getGroupIdentities(requestGroups, realm);

            Set<AMIdentity> toAdd = new HashSet(newGroups);
            toAdd.removeAll(currentGroups);
            Set<AMIdentity> toRemove = new HashSet(currentGroups);
            toRemove.removeAll(newGroups);
            for (AMIdentity group : toAdd) {
                group.addMember(user);
            }
            for (AMIdentity group : toRemove) {
                group.removeMember(user);
            }

            JsonValue result = readGroups(user);
            return newResultPromise(newResourceResponse(userName,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("UserGroupResource.updateInstance() :: Cannot UPDATE {}'s groups", userName, e);
            return new InternalServerErrorException("Unable to update groups").asPromise();
        } catch (IdRepoException e) {
            logger.error("UserGroupResource.updateInstance() :: Cannot UPDATE {}'s groups", userName, e);
            return new InternalServerErrorException("Unable to update groups").asPromise();
        } catch (BadRequestException e) {
            return e.asPromise();
        }
    }

    private Set<AMIdentity> getGroupIdentities(Set<String> groups, String realm)
            throws SSOException, IdRepoException, BadRequestException {
        Set<AMIdentity> result = new HashSet<AMIdentity>();

        final AMIdentityRepository amIdRepo = IdUtils.getAMIdentityRepository(DNMapper.orgNameToDN(realm));
        final IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);

        for (String groupName : groups) {
            AMIdentity amIdentity;
            Set<AMIdentity> results = Collections.emptySet();

            idsc.setMaxResults(0);
            IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.GROUP, groupName, idsc, false, false);
            if (searchResults != null) {
                results = searchResults.getSearchResults();
            }

            if (results.isEmpty()) {
                logger.warning("UserGroupResource.getGroupIdentities() : Group {} is not found", groupName);
                throw new BadRequestException("'" + GROUPS + "' attribute is invalid.");
            } else if (results.size() > 1) {
                logger.warning("UserGroupResource.getGroupIdentities() : More than one group found for the group {}",
                        groupName);
                throw new BadRequestException("'" + GROUPS + "' attribute is invalid.");
            }

            amIdentity = results.iterator().next();
            result.add(amIdentity);
        }
        return result;
    }

    private JsonValue createSchema(Context context) {
        ResourceBundle schemaI18n = ResourceBundle.getBundle(I18N_FILE, getLocale(context));
        JsonValue result = json(object(field(TYPE, OBJECT_TYPE)));
        String path = "/" + PROPERTIES + "/groups";
        result.addPermissive(new JsonPointer(path+ "/" + TITLE),
                schemaI18n.getString(I18N_PREFIX + TITLE));
        result.addPermissive(new JsonPointer(path + "/" + DESCRIPTION),
                schemaI18n.getString(I18N_PREFIX + DESCRIPTION));
        result.addPermissive(new JsonPointer(path + "/" + PROPERTY_ORDER), 100);
        result.addPermissive(new JsonPointer(path + "/" + REQUIRED), false);
        result.addPermissive(new JsonPointer(path + "/" + ITEMS),
                object(field(TYPE, STRING_TYPE)));
        result.addPermissive(new JsonPointer(path + "/" + TYPE), ARRAY_TYPE);
        result.addPermissive(new JsonPointer(path + "/" + EXAMPLE_VALUE), "");
        return result;
    }

    private JsonValue readGroups(AMIdentity user) throws SSOException, IdRepoException {
        Set<AMIdentity> identities = user.getMemberships(IdType.GROUP);
        Set<String> groups = new HashSet<String>();
        for (AMIdentity identity : identities) {
            groups.add(identity.getName());
        }
        return json(object(field(GROUPS, groups)));
    }

    private Locale getLocale(Context context) {
        return context.asContext(LocaleContext.class).getLocale();
    }

    private AMIdentity getIdentity(String userName, String realm) {
        return IdUtils.getIdentity(userName, realm);
    }
}
