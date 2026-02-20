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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.openam.core.rest.IdentityRestUtils;
import org.forgerock.openam.core.rest.sms.SmsJsonConverter;
import org.forgerock.openam.utils.CollectionUtils;

import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.ServiceSchema;

import jp.co.osstech.openam.core.rest.sms.AttributeSchemaFilter;

/**
 * SmsJsonConverter implementation for iPlanetAMUserService.
 *
 * This class relaxes type conversion validation according to AttributeSchema.
 */
public class UserJsonConverter extends SmsJsonConverter {

    private final AttributeSchemaFilter filter;

    public UserJsonConverter(ServiceSchema schema, AttributeSchemaFilter filter) {
        super(schema);
        this.filter = filter;
    }

    @Override
    protected AttributeSchemaConverter getAttributeSchemaValue(AttributeSchema.Syntax syntax) {
        AttributeSchemaConverter attributeSchemaConverter;
        if (isBoolean(syntax)) {
            attributeSchemaConverter = new BooleanAttributeSchemaValue();
        } else if (isDouble(syntax)) {
            attributeSchemaConverter = new DoubleAttributeSchemaValue();
        } else if (isInteger(syntax)) {
            attributeSchemaConverter = new IntegerOrStringAttributeSchemaValue();
        } else if (isScript(syntax)) {
            attributeSchemaConverter = new ScriptAttributeSchemaValue();
        } else if (isPassword(syntax)) {
            attributeSchemaConverter = new PasswordAttributeSchemaValue();
        } else {
            attributeSchemaConverter = new StringAttributeSchemaValue();
        }
        return attributeSchemaConverter;
    }

    @Override
    public Map<String, Set<String>> fromJson(String realm, JsonValue jsonValue) throws JsonException, BadRequestException {
        if (!initialised) {
            init();
        }

        Map<String, Set<String>> result = new HashMap<>();
        if (jsonValue == null || jsonValue.isNull()) {
            return result;
        }

        // Check for the existence of required attribute keys
        for (AttributeSchema as : schema.getAttributeSchemas()) {
            String attributeName = as.getName();
            if (filter.isTarget(as) && filter.isRequired(as)
                    && !IdentityRestUtils.isPasswordAttribute(attributeName)) {
                boolean found = false;
                for (String jsonKey : jsonValue.keys()) {
                    if (attributeName.toLowerCase().equals(jsonKey.toLowerCase())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    throw new BadRequestException(attributeName + " is not specified");
                }
            }
        }

        for (String jsonKey : jsonValue.keys()) {

            // Ignore _id field used to name resource when creating
            if (ResourceResponse.FIELD_CONTENT_ID.equals(jsonKey)) {
                continue;
            }

            // Get AttributeSchema by case insensitive name.
            AttributeSchema as = getAttributeSchema(jsonKey);
            if (as == null) {
                throw new BadRequestException("Invalid attribute specified");
            }

            String attributeName = as.getName();
            Set<String> value = new HashSet<>();
            final Object attributeValue = jsonValue.get(jsonKey).getObject();
            if (attributeValue instanceof HashMap) {
                // Do nothing
            } else if (attributeValue instanceof List) {
                List<Object> attributeArray = (ArrayList<Object>) attributeValue;
                for (Object val : attributeArray) {
                    value.add(convertJsonToString(attributeName, val));
                }
            } else if (attributeValue != null) {
                value.add(convertJsonToString(attributeName, attributeValue));
            }

            // Return Bad Request if any required attribute is empty
            boolean isEmpty = isEmptyAttribute(value);
            if (filter.isRequired(as) && isEmpty
                    && !IdentityRestUtils.isPasswordAttribute(attributeName)) {
                throw new BadRequestException(attributeName + " is not specified");
            }

            if (!isEmpty) {
                result.put(attributeName, value);
            } else if (!isPassword(schema.getAttributeSchema(attributeName).getSyntax())) {
                // If the password is empty, it will be ignored, otherwise it will be deleted.
                result.put(attributeName,  Collections.<String>emptySet());
            }
        }

        return result;
    }

    private AttributeSchema getAttributeSchema(String name) {
        for (AttributeSchema as : schema.getAttributeSchemas()) {
            if (filter.isTarget(as)) {
                String attributeName = as.getName();
                if (attributeName.toLowerCase().equals(name.toLowerCase())) {
                    return as;
                }
            }
        }
        return null;
    }

    private boolean isEmptyAttribute(Set<String> attrSet) {
        if (CollectionUtils.isEmpty(attrSet)) {
            return true;
        }
        for (String attr : attrSet) {
            if (attr != null && !attr.isEmpty()) {
                return false;
            }
        }
        return true;
    }

    private static class IntegerOrStringAttributeSchemaValue implements AttributeSchemaConverter {
        @Override
        public Object toJson(String value) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                return value;
            }
        }

        @Override
        public String fromJson(Object json) {
            if (json instanceof Integer) {
                return Integer.toString((Integer) json);
            }
            return (String) json;
        }
    }
}
