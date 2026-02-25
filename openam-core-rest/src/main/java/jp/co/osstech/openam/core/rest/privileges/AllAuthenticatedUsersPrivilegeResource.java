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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.rest.RestConstants.COLLECTION;
import static org.forgerock.openam.rest.RestConstants.NAME;
import static org.forgerock.openam.rest.RestUtils.realmFor;
import static org.forgerock.util.promise.Promises.newResultPromise;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import com.iplanet.sso.SSOException;
import com.sun.identity.delegation.DelegationException;
import com.sun.identity.delegation.DelegationManager;

/**
 * REST resource for All Authenticated Users Privileges.
 */
public class AllAuthenticatedUsersPrivilegeResource extends PrivilegeResourceBase {

    private static final String RESOURCE_ID = "allauthenticatedusers";

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, ReadRequest request) {
        final String realm = realmFor(context);

        try {
            DelegationManager mgr = new DelegationManager(RestUtils.getToken(), realm);

            JsonValue result = readPrivilege(mgr, RESOURCE_ID, DelegationManager.AUTHN_USERS_ID);
            return newResultPromise(newResourceResponse(RESOURCE_ID,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("AllAuthenticatedUsersPrivilegeResource.readInstance() :: Cannot READ privilege", e);
            return new InternalServerErrorException("Unable to read privilege").asPromise();
        } catch (DelegationException e) {
            logger.error("AllAuthenticatedUsersPrivilegeResource.readInstance() :: Cannot READ privilege", e);
            return new InternalServerErrorException("Unable to read privilege").asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, UpdateRequest request) {
        final String realm = realmFor(context);

        try {
            DelegationManager mgr = new DelegationManager(RestUtils.getToken(), realm);

            final JsonValue content = request.getContent();
            writePrivilege(mgr, DelegationManager.AUTHN_USERS_ID, content, realm);

            JsonValue result = readPrivilege(mgr, RESOURCE_ID, DelegationManager.AUTHN_USERS_ID);
            return newResultPromise(newResourceResponse(RESOURCE_ID,
                    String.valueOf(result.getObject().hashCode()), result));
        } catch (SSOException e) {
            logger.error("AllAuthenticatedUsersPrivilegeResource.updateInstance() :: Cannot UPDATE privilege", e);
            return new InternalServerErrorException("Unable to update privilege").asPromise();
        } catch (DelegationException e) {
            logger.error("AllAuthenticatedUsersPrivilegeResource.updateInstance() :: Cannot UPDATE privilege", e);
            return new InternalServerErrorException("Unable to update privilege").asPromise();
        } catch (BadRequestException e) {
            logger.error("AllAuthenticatedUsersPrivilegeResource.updateInstance() :: Cannot UPDATE privilege", e);
            return e.asPromise();
        }
    }

    @Override
    protected JsonValue readPrivilege(DelegationManager mgr, String resourceId, String univId)
            throws DelegationException {
        JsonValue result = super.readPrivilege(mgr, resourceId, univId);
        result.add("_type", getTypeValue());
        return result;
    }

    private Object getTypeValue() {
        return object(
                field(ResourceResponse.FIELD_CONTENT_ID, RESOURCE_ID),
                field(NAME, "All Authenticated Users"),
                field(COLLECTION, false));
    }
}
