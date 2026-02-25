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
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.BOOLEAN_TYPE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.DESCRIPTION;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.EXAMPLE_VALUE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.OBJECT_TYPE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.PROPERTIES;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.PROPERTY_ORDER;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.REQUIRED;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.TITLE;
import static org.forgerock.openam.core.rest.sms.SmsJsonSchema.TYPE;
import static org.forgerock.openam.rest.RestConstants.SCHEMA;
import static org.forgerock.openam.rest.RestUtils.realmFor;

import java.util.HashSet;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.SingletonResourceProvider;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.rest.resource.LocaleContext;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import com.iplanet.sso.SSOException;
import com.sun.identity.delegation.DelegationException;
import com.sun.identity.delegation.DelegationManager;
import com.sun.identity.delegation.DelegationPrivilege;
import com.sun.identity.shared.debug.Debug;

/**
 * Base implementation of REST resource for Privileges.
 */
public abstract class PrivilegeResourceBase implements SingletonResourceProvider {

    private static final String I18N_FILE = "schemaI18n";
    private static final String I18N_PREFIX = "privilege.";

    protected static Debug logger = Debug.getInstance("frRest");

    @Override
    public Promise<ActionResponse, ResourceException> actionInstance(Context context, ActionRequest request) {
        try {
            switch (request.getAction()) {
                case SCHEMA:
                    return newActionResponse(createSchema(context, realmFor(context))).asPromise();
                default:
            }
        } catch (ResourceException re) {
            return re.asPromise();
        }
        return new NotSupportedException("Not supported").asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context context, PatchRequest request) {
        return new NotSupportedException("Not supported").asPromise();
    }

    /**
     * Reads privilege for the specified universal id.
     *
     * @param mgr DelegationManager instance
     * @param resourceId the resource id
     * @param univId the universal id
     * @return the privilege json
     * @throws DelegationException
     */
    protected JsonValue readPrivilege(DelegationManager mgr, String resourceId, String univId)
            throws DelegationException {
        JsonValue result = json(object());
        result.add(ResourceResponse.FIELD_CONTENT_ID, resourceId);
        Set<String> allPrivilegeNames = mgr.getConfiguredPrivilegeNames();
        Set<DelegationPrivilege> groupPrivileges = mgr.getPrivileges(univId);
        for (String privilegeName : allPrivilegeNames) {
            DelegationPrivilege privilege = findDelegationPrivilege(privilegeName, groupPrivileges);
            if (privilege != null) {
                result.add(privilegeName, true);
            } else {
                result.add(privilegeName, false);
            }
        }
        return result;
    }

    /**
     * Writes privilege for the specified universal id.
     *
     * @param mgr DelegationManager instance
     * @param univId the universal id
     * @param content the request context
     * @param realm the realm
     * @throws DelegationException
     * @throws BadRequestException
     */
    protected void writePrivilege(DelegationManager mgr, String univId, JsonValue content, String realm)
            throws DelegationException, BadRequestException {
        Set<DelegationPrivilege> realmPrivileges = mgr.getPrivileges();
        Set<String> allPrivilegeNames = mgr.getConfiguredPrivilegeNames();
        Set<DelegationPrivilege> targets = new HashSet<>();

        for (String jsonKey : content.keys()) {

            // Ignore _id field used to name resource when creating
            if (ResourceResponse.FIELD_CONTENT_ID.equals(jsonKey)
                    || "_type".equals(jsonKey)) {
                continue;
            }

            if (allPrivilegeNames.contains(jsonKey)) {
                String privilegeName = jsonKey;
                JsonValue reqValue = content.get(privilegeName);
                if (!reqValue.isBoolean()) {
                    throw new BadRequestException("Invalid attribute value syntax");
                }
                DelegationPrivilege privilege = findDelegationPrivilege(privilegeName,
                        realmPrivileges);
                if (privilege != null) {
                    Set<String> subjects = privilege.getSubjects();
                    boolean modified = false;
                    if (reqValue.asBoolean()) {
                        modified = subjects.add(univId);
                    } else {
                        modified = subjects.remove(univId);
                    }
                    if (modified) {
                        targets.add(privilege);
                    }
                } else if (reqValue.asBoolean()) {
                    DelegationPrivilege nePrivilege = new DelegationPrivilege(privilegeName,
                            CollectionUtils.asSet(univId), realm);
                    targets.add(nePrivilege);
                }
            } else {
                throw new BadRequestException("Invalid attribute specified");
            }
        }

        // Update privileges
        for (DelegationPrivilege target : targets) {
            mgr.addPrivilege(target);
        }
    }

    /**
     * Find the target DelegationPrivilege by name.
     *
     * @param privilegeName the privilege name
     * @param groupPrivileges Set of privilege
     * @return the target DelegationPrivilege by name
     */
    protected DelegationPrivilege findDelegationPrivilege(String privilegeName,
            Set<DelegationPrivilege> groupPrivileges) {
        for (DelegationPrivilege privilege : groupPrivileges) {
            if (privilege.getName().equals(privilegeName)) {
                return privilege;
            }
        }
        return null;
    }

    /**
     * Returns the client's preferred locale.
     *
     * @param context the request context
     * @return the client's preferred locale
     */
    protected Locale getLocale(Context context) {
        return context.asContext(LocaleContext.class).getLocale();
    }

    private JsonValue createSchema(Context context, String realm)
            throws InternalServerErrorException {
        Set<String> privilegeNames;
        try {
            DelegationManager mgr = new DelegationManager(RestUtils.getToken(), realm);
            privilegeNames = mgr.getConfiguredPrivilegeNames();
        } catch (SSOException e) {
            logger.error("PrivilegeResourceBase.createSchema() :: Cannot retrieve privilege", e);
            throw new InternalServerErrorException("Unable to create schema");
        } catch (DelegationException e) {
            logger.error("PrivilegeResourceBase.createSchema() :: Cannot retrieve privilege", e);
            throw new InternalServerErrorException("Unable to create schema");
        }

        JsonValue result = json(object(field(TYPE, OBJECT_TYPE)));
        ResourceBundle schemaI18n = ResourceBundle.getBundle(I18N_FILE, getLocale(context));
        int count = 1;
        for (String privilegeName : privilegeNames) {
            String path = "/" + PROPERTIES + "/" + privilegeName;
            String prefix = I18N_PREFIX + privilegeName + ".";
            result.addPermissive(new JsonPointer(path+ "/" + TITLE),
                    schemaI18n.getString(prefix + TITLE));
            result.addPermissive(new JsonPointer(path + "/" + DESCRIPTION),
                    schemaI18n.getString(prefix + DESCRIPTION));
            result.addPermissive(new JsonPointer(path + "/" + PROPERTY_ORDER), 100 * count++);
            result.addPermissive(new JsonPointer(path + "/" + REQUIRED), false);
            result.addPermissive(new JsonPointer(path + "/" + TYPE), BOOLEAN_TYPE);
            result.addPermissive(new JsonPointer(path + "/" + EXAMPLE_VALUE), "");
        }
        return result;
    }
}
