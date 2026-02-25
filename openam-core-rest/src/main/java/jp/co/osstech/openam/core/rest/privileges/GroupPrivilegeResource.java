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
package jp.co.osstech.openam.core.rest.privileges;

import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.rest.RestUtils.realmFor;
import static org.forgerock.util.promise.Promises.newResultPromise;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import com.iplanet.sso.SSOException;
import com.sun.identity.delegation.DelegationException;
import com.sun.identity.delegation.DelegationManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;

/**
 * REST resource for Group Privileges.
 */
public class GroupPrivilegeResource extends PrivilegeResourceBase {

    private final ContextHelper contextHelper;

    @Inject
    public GroupPrivilegeResource(ContextHelper helper) {
        this.contextHelper = helper;
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, ReadRequest request) {
        final String realm = realmFor(context);
        String groupId = contextHelper.getGroupId(context);

        AMIdentity group = IdUtils.getGroupIdentity(groupId, realm);
        if (group == null) {
            return new NotFoundException("Resource not found").asPromise();
        }

        try {
            DelegationManager mgr = new DelegationManager(RestUtils.getToken(), realm);

            JsonValue result = readPrivilege(mgr, groupId, group.getUniversalId());
            return newResultPromise(newResourceResponse(groupId,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("GroupPrivilegeResource.readInstance() :: Cannot READ privilege", e);
            return new InternalServerErrorException("Unable to read privilege").asPromise();
        } catch (DelegationException e) {
            logger.error("GroupPrivilegeResource.readInstance() :: Cannot READ privilege", e);
            return new InternalServerErrorException("Unable to read privilege").asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, UpdateRequest request) {
        final String realm = realmFor(context);
        String groupId = contextHelper.getGroupId(context);

        AMIdentity group = IdUtils.getGroupIdentity(groupId, realm);
        if (group == null) {
            return new NotFoundException("Resource not found").asPromise();
        }

        try {
            DelegationManager mgr = new DelegationManager(RestUtils.getToken(), realm);

            final JsonValue content = request.getContent();
            writePrivilege(mgr, group.getUniversalId(), content, realm);

            JsonValue result = readPrivilege(mgr, groupId, group.getUniversalId());
            return newResultPromise(newResourceResponse(groupId,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("GroupPrivilegeResource.updateInstance() :: Cannot UPDATE privilege", e);
            return new InternalServerErrorException("Unable to update privilege").asPromise();
        } catch (DelegationException e) {
            logger.error("GroupPrivilegeResource.updateInstance() :: Cannot UPDATE privilege", e);
            return new InternalServerErrorException("Unable to update privilege").asPromise();
        } catch (BadRequestException e) {
            logger.error("GroupPrivilegeResource.updateInstance() :: Cannot UPDATE privilege", e);
            return e.asPromise();
        }
    }
}
