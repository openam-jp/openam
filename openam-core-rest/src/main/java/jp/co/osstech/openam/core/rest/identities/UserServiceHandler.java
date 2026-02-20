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
import static org.forgerock.openam.rest.RestConstants.COLLECTION;
import static org.forgerock.openam.rest.RestConstants.NAME;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.Set;

import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.openam.core.rest.sms.SmsJsonConverter;
import org.forgerock.openam.core.rest.sms.SmsJsonSchema;
import org.forgerock.openam.rest.RestUtils;

import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;
import com.sun.identity.sm.ServiceSchemaManager;

/**
 * This class handles services that can be assigned to users.
 */
public class UserServiceHandler {

    private static Debug logger = Debug.getInstance("frRest");

    private final ServiceSchemaManager mgr;
    private final String serviceName;
    private final String resourceName;
    private final ServiceSchema ss;
    private final SmsJsonConverter converter;
    private final AMResourceBundleCache resourceBundleCache;

    /**
     * Constructor.
     *
     * @param serviceName the service name
     * @param resourceBundleCache the resource bundle cache
     * @throws SMSException
     * @throws SSOException
     */
    public UserServiceHandler(String serviceName, AMResourceBundleCache resourceBundleCache)
            throws SMSException, SSOException {
        this.serviceName = serviceName;
        this.resourceBundleCache = resourceBundleCache;
        mgr = new ServiceSchemaManager(serviceName, RestUtils.getToken());
        resourceName = mgr.getResourceName();
        ss = mgr.getSchema(IdType.USER.getName());
        converter = new SmsJsonConverter(ss);
    }

    /**
     * Returns the service name.
     *
     * @return the service name
     */
    public String getServiceName() {
        return serviceName;
    }

    /**
     * Returns the resource name.
     *
     * @return the resource name
     */
    public String getResourceName() {
        return resourceName;
    }

    /**
     * Assigns the service to the user.
     *
     * @param user the user
     * @param realm the realm
     * @param parameter the request JSON parameter
     * @param locale the locale
     * @return JSON with service attributes from the user
     * @throws SSOException
     * @throws IdRepoException
     * @throws ResourceException
     */
    public JsonValue createService(AMIdentity user, String realm, JsonValue parameter, Locale locale)
            throws SSOException, IdRepoException, ResourceException {
      Set<String> assignable = user.getAssignableServices();
      if (!assignable.contains(serviceName)) {
          throw new BadRequestException("The service is already assigned");
      }
      Map<String, Set<String>> atrMap = convertToUpdate(parameter);
      user.assignService(serviceName, atrMap);

      return readService(user, realm, locale);
    }

    /**
     * Returns the service attributes from the user.
     *
     * @param user the user
     * @param realm the realm
     * @param locale the locale
     * @return JSON with service attributes from the user
     * @throws SSOException
     * @throws IdRepoException
     * @throws ResourceException
     */
    public JsonValue readService(AMIdentity user, String realm, Locale locale)
            throws SSOException, IdRepoException, ResourceException {
        Set<String> assigned = user.getAssignedServices();
        if (!assigned.contains(serviceName)) {
            throw new BadRequestException("The service is not assigned");
        }
        JsonValue result = json(object());
        result.add(ResourceResponse.FIELD_CONTENT_ID, resourceName);
        Map<String, Set<String>> atrMap = user.getServiceAttributes(serviceName);
        converter.toJson(realm, atrMap, false, result);
        result.add("_type", getTypeValue(locale));
        return result;
    }

    /**
     * Updates the service attributes in the user.
     *
     * @param user the user
     * @param realm the realm
     * @param parameter the request JSON parameter
     * @param locale the locale
     * @return JSON with service attributes from the user
     * @throws SSOException
     * @throws IdRepoException
     * @throws ResourceException
     */
    public JsonValue updateService(AMIdentity user, String realm, JsonValue parameter, Locale locale)
            throws SSOException, IdRepoException, ResourceException {
        Set<String> assigned = user.getAssignedServices();
        if (!assigned.contains(serviceName)) {
            throw new BadRequestException("The service is not assigned");
        }
        Map<String, Set<String>> atrMap = convertToUpdate(parameter);
        user.modifyService(serviceName, atrMap);

        return readService(user, realm, locale);
    }

    /**
     * Unassigns the service to the user.
     *
     * @param user the user
     * @param realm the realm
     * @return JSON value indicating success
     * @throws SSOException
     * @throws IdRepoException
     * @throws ResourceException
     */
    public JsonValue deleteService(AMIdentity user, String realm)
            throws SSOException, IdRepoException, ResourceException {
        Set<String> assigned = user.getAssignedServices();
        if (!assigned.contains(serviceName)) {
            throw new BadRequestException("The service is not assigned");
        }
        user.unassignService(serviceName);

        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>(1));
        result.put("success", true);
        return result;
    }

    /**
     * Returns JSON with service schema.
     *
     * @param locale locale
     * @param realm the realm
     * @return JSON with service schema
     */
    public JsonValue createSchema(Locale locale, String realm) {
        JsonValue result = json(object(field("type", "object")));
        SmsJsonSchema.addAttributeSchema(result, "/properties/", ss,
                locale, realm);
        return result;
    }

    /**
     * Returns JSON with attribute defaults.
     *
     * @return JSON with attribute defaults
     */
    public JsonValue createTemplate() {
        return converter.toJson(ss.getAttributeDefaults(), false);
    }


    /**
     * Returns type object for _type.
     *
     * @param locale the locale
     * @return type object for _type
     */
    public Object getTypeValue(Locale locale) {
        return object(
                field(ResourceResponse.FIELD_CONTENT_ID, resourceName),
                field(NAME, getLocalizedServiceName(locale)),
                field(COLLECTION, false));
    }

    private Map<String, Set<String>> convertToUpdate(JsonValue parameter)
            throws BadRequestException, JsonException {
        Map<String, Set<String>> result = converter.fromJson(parameter);

        // Convert Set with empty string to empty Set
        for(Map.Entry<String, Set<String>> entry : result.entrySet()) {
            Set<String> values = entry.getValue();
            if (values != null && values.size() == 1
                    && values.iterator().next().isEmpty()) {
                result.put(entry.getKey(), Collections.<String>emptySet());
            }
        }
        return result;
    }

    private Object getLocalizedServiceName(Locale locale) {
        String i18nName = serviceName;
        try {
            String rbName = mgr.getI18NFileName();

            if ((rbName != null) && (rbName.trim().length() > 0)) {
                ResourceBundle rb = resourceBundleCache.getResBundle(rbName, locale);

                String i18nKey = null;
                Set types = mgr.getSchemaTypes();
                if (!types.isEmpty()) {
                    SchemaType type = (SchemaType)types.iterator().next();
                    ServiceSchema schema = mgr.getSchema(type);
                    if (schema != null) {
                        i18nKey = schema.getI18NKey();
                    }
                }

                if ((i18nKey != null) && (i18nKey.length() > 0)) {
                    i18nName = rb.containsKey(i18nKey) ? rb.getString(i18nKey) : serviceName;
                }
            }
        } catch (SMSException e) {
            logger.error(
                    "UserServiceHandler.getLocalizedServiceName() :: Failed to get localized service name", e);
        } catch (MissingResourceException e) {
            logger.error(
                    "UserServiceHandler.getLocalizedServiceName() :: Failed to get localized service name", e);
        }

        return i18nName;
    }
}
