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
 * Copyright 2015 ForgeRock AS.
 * Portions copyright 2026 OSSTech Corporation
 */

package org.forgerock.openam.core.rest.sms;

import static com.sun.identity.sm.AttributeSchema.Syntax.BOOLEAN;
import static com.sun.identity.sm.AttributeSchema.Syntax.DECIMAL;
import static com.sun.identity.sm.AttributeSchema.Syntax.DECIMAL_NUMBER;
import static com.sun.identity.sm.AttributeSchema.Syntax.DECIMAL_RANGE;
import static com.sun.identity.sm.AttributeSchema.Syntax.NUMBER;
import static com.sun.identity.sm.AttributeSchema.Syntax.NUMBER_RANGE;
import static com.sun.identity.sm.AttributeSchema.Syntax.PERCENT;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.Context;

import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;

import jp.co.osstech.openam.core.rest.sms.AttributeSchemaFilter;
import jp.co.osstech.openam.core.rest.sms.DefaultAttributeSchemaFilter;

/**
 * Utility for the REST SMS schema representations.
 */
public class SmsJsonSchema {

    public static final String OBJECT_TYPE = "object";
    public static final String TYPE = "type";
    public static final String FORMAT = "format";
    public static final String STRING_TYPE = "string";
    public static final String PASSWORD_TYPE = "password";
    public static final String PATTERN_PROPERTIES = "patternProperties";
    public static final String ARRAY_TYPE = "array";
    public static final String ITEMS = "items";
    public static final String PROPERTIES = "properties";
    public static final String TITLE = "title";
    public static final String PROPERTY_ORDER = "propertyOrder";
    public static final String DESCRIPTION = "description";
    public static final String REQUIRED = "required";
    public static final String EXAMPLE_VALUE = "exampleValue";
    public static final String ENUM = "enum";
    public static final String NUMBER_TYPE = "number";
    public static final String BOOLEAN_TYPE = "boolean";
    public static final String READONLY = "readonly";

    static final List<AttributeSchema.Syntax> NUMBER_SYNTAXES = Arrays.asList(NUMBER, DECIMAL, PERCENT, NUMBER_RANGE, DECIMAL_RANGE, DECIMAL_NUMBER);
    static final Debug debug = Debug.getInstance("frRest");
    static final AttributeSchemaFilter filter = new DefaultAttributeSchemaFilter();

    private SmsJsonSchema() {}

    /**
     * Adds the attribute schema json to the JsonValue instance.
     *
     * @param result the JsonValue instance
     * @param path the json path
     * @param schemas the service schema
     * @param locale the request locale
     * @param realm the realm
     */
    public static void addAttributeSchema(JsonValue result, String path, ServiceSchema schemas,
            Locale locale, String realm) {
        addAttributeSchema(result, path, schemas, locale, realm, filter);
    }

    /**
     * Adds the attribute schema json to the JsonValue instance.
     *
     * @param result the JsonValue instance
     * @param path the json path
     * @param schemas the service schema
     * @param locale the request locale
     * @param realm the realm
     * @param filter the filter to optimize for the service
     */
    public static void addAttributeSchema(JsonValue result, String path, ServiceSchema schemas,
            Locale locale, String realm, AttributeSchemaFilter filter) {
        Map<String, String> attributeSectionMap = getAttributeNameToSection(schemas);
        ResourceBundle consoleI18n = ResourceBundle.getBundle("amConsole", locale);
        String serviceType = schemas.getServiceType().getType();
        String serviceName = schemas.getServiceName();
        List<String> sections = getSections(serviceName, attributeSectionMap, consoleI18n, serviceType);

        ResourceBundle schemaI18n = ResourceBundle.getBundle(schemas.getI18NFileName(), locale);

        for (AttributeSchema attribute : schemas.getAttributeSchemas()) {
            if (filter.isTarget(attribute)) {
                String attributePath = attribute.getResourceName();
                if (!sections.isEmpty()) {
                    String section = attributeSectionMap.get(attribute.getName());
                    if (section != null) {
                        String sectionLabel = "section.label." + serviceName + "." + serviceType + "." + section;
                        attributePath = section + "/" + PROPERTIES + "/" + attributePath;
                        result.putPermissive(new JsonPointer(path + section + "/" + TYPE), OBJECT_TYPE);
                        result.putPermissive(new JsonPointer(path + section + "/" + TITLE),
                                getTitle(consoleI18n, schemaI18n, sectionLabel));
                        result.putPermissive(new JsonPointer(path + section + "/" + PROPERTY_ORDER), sections.indexOf(section));
                    }
                }

                String i18NKey = attribute.getI18NKey();
                Object propertyOrder = (attribute.getOrder() == null) ? i18NKey : attribute.getOrder();
                result.addPermissive(new JsonPointer(path + attributePath + "/" + TITLE),
                        schemaI18n.containsKey(i18NKey) ? schemaI18n.getString(i18NKey) : i18NKey);
                result.addPermissive(new JsonPointer(path + attributePath + "/" + DESCRIPTION),
                        getSchemaDescription(schemaI18n, i18NKey));
                result.addPermissive(new JsonPointer(path + attributePath + "/" + PROPERTY_ORDER), propertyOrder);
                result.addPermissive(new JsonPointer(path + attributePath + "/" + REQUIRED), filter.isRequired(attribute));
                addType(result, path + attributePath, attribute, schemaI18n, consoleI18n, realm, schemas.getServiceType());
                addExampleValue(result, path, attribute, attributePath);
            }
        }
    }

    /**
     * Returns the description text of the attribute schema.
     *
     * @param i18n the resource bundle instance
     * @param i18NKey the value of the i18nKey
     * @return the description text
     */
    public static String getSchemaDescription(ResourceBundle i18n, String i18NKey) {
        StringBuilder description = new StringBuilder();
        if (i18n.containsKey(i18NKey + ".help")) {
            description.append(i18n.getString(i18NKey + ".help"));
        }
        if (i18n.containsKey(i18NKey + ".help.txt")) {
            if (description.length() > 0) {
                description.append("<br><br>");
            }
            description.append(i18n.getString(i18NKey + ".help.txt"));
        }
        return description.toString();
    }

    private static String getTitle(ResourceBundle consoleI18n, ResourceBundle schemaI18n, String title) {
        String result = getConsoleString(consoleI18n, title);
        if (result.equals("")) {
            result = getConsoleString(schemaI18n, title);
        }

        return result;
    }

    private static List<String> getSections(String serviceName, Map<String, String> attributeSectionMap, ResourceBundle console, String serviceType) {

        List<String> sections = new ArrayList<>();
        String sectionOrder = getConsoleString(console, "sections." + serviceName + "." + serviceType);

        if (StringUtils.isNotEmpty(sectionOrder)) {
            sections.addAll(Arrays.asList(sectionOrder.split("\\s+")));
        }

        if (sections.isEmpty()) {
            for (String attributeSection : attributeSectionMap.values()) {
                if (!sections.contains(attributeSection)) {
                    sections.add(attributeSection);
                }
            }
        }
        return sections;
    }

    private static void addExampleValue(JsonValue result, String path, AttributeSchema attribute, String attributePath) {
        final Iterator iterator = attribute.getExampleValues().iterator();
        String exampleValue = "";
        if (iterator.hasNext()) {
            exampleValue = (String) iterator.next();
        }
        result.addPermissive(new JsonPointer(path + attributePath + "/" + EXAMPLE_VALUE), exampleValue);
    }

    private static String getConsoleString(ResourceBundle console, String key) {
        try {
            return console.getString(key);
        } catch (MissingResourceException e) {
            return "";
        }
    }

    private static void addType(JsonValue result, String pointer, AttributeSchema attribute, ResourceBundle schemaI18n,
                         ResourceBundle consoleI18n, String realm, SchemaType schemaType) {
        String type = null;
        AttributeSchema.Type attributeType = attribute.getType();
        AttributeSchema.Syntax syntax = attribute.getSyntax();
        if (attributeType == AttributeSchema.Type.LIST && (
                attribute.getUIType() == AttributeSchema.UIType.GLOBALMAPLIST ||
                attribute.getUIType() == AttributeSchema.UIType.MAPLIST)) {
            type = OBJECT_TYPE;
            JsonValue fieldType = json(object());
            if (attribute.hasChoiceValues()) {
                addEnumChoices(fieldType, attribute, schemaI18n, consoleI18n, realm, schemaType);
            } else {
                fieldType.add(TYPE, STRING_TYPE);
            }
            result.addPermissive(new JsonPointer(pointer + "/" + PATTERN_PROPERTIES),
                    object(field(".*", fieldType.getObject())));
        } else if (attributeType == AttributeSchema.Type.LIST) {
            type = ARRAY_TYPE;
            result.addPermissive(new JsonPointer(pointer + "/" + ITEMS),
                    object(field(TYPE, getTypeFromSyntax(attribute.getSyntax()))));
            if (attribute.hasChoiceValues()) {
                addEnumChoices(result.get(new JsonPointer(pointer + "/" + ITEMS)), attribute, schemaI18n, consoleI18n,
                        realm, schemaType);
            }
        } else if (attributeType.equals(AttributeSchema.Type.MULTIPLE_CHOICE)) {
            type = ARRAY_TYPE;
            result.addPermissive(new JsonPointer(pointer + "/" + ITEMS),
                    object(field(TYPE, getTypeFromSyntax(attribute.getSyntax()))));
            addEnumChoices(result.get(new JsonPointer(pointer + "/" + ITEMS)), attribute, schemaI18n, consoleI18n,
                    realm, schemaType);
        } else if (attributeType.equals(AttributeSchema.Type.SINGLE_CHOICE)) {
            addEnumChoices(result.get(new JsonPointer(pointer)), attribute, schemaI18n, consoleI18n, realm, schemaType);
        } else {
            type = getTypeFromSyntax(syntax);
        }
        if (type != null) {
            result.addPermissive(new JsonPointer(pointer + "/" + TYPE), type);
        }
        if (AttributeSchema.Syntax.PASSWORD.equals(syntax)) {
            result.addPermissive(new JsonPointer(pointer + "/" + FORMAT), PASSWORD_TYPE);
        }
    }

    private static void addEnumChoices(JsonValue jsonValue, AttributeSchema attribute, ResourceBundle schemaI18n,
                                ResourceBundle consoleI18n, String realm, SchemaType schemaType) {
        List<String> values = new ArrayList<String>();
        List<String> descriptions = new ArrayList<String>();
        Map environment = schemaType == SchemaType.GLOBAL ? Collections.emptyMap() :
                Collections.singletonMap(Constants.ORGANIZATION_NAME, realm);
        Map<String, String> valuesMap = attribute.getChoiceValuesMap(environment);
        for (Map.Entry<String, String> value : valuesMap.entrySet()) {
            values.add(value.getKey());
            if (AttributeSchema.UIType.SCRIPTSELECT.equals(attribute.getUIType())) {
                if (value.getValue() != null && consoleI18n.containsKey(value.getValue())) {
                    descriptions.add(consoleI18n.getString(value.getValue()));
                } else {
                    descriptions.add(value.getValue());
                }
            } else if (value.getValue() != null && schemaI18n.containsKey(value.getValue())) {
                descriptions.add(schemaI18n.getString(value.getValue()));
            } else {
                descriptions.add(value.getKey());
            }
        }
        jsonValue.add(ENUM, values);
        jsonValue.putPermissive(new JsonPointer("options/enum_titles"), descriptions);
    }

    private static String getTypeFromSyntax(AttributeSchema.Syntax syntax) {
        String type;
        if (syntax == BOOLEAN) {
            type = BOOLEAN_TYPE;
        } else if (NUMBER_SYNTAXES.contains(syntax)) {
            type = NUMBER_TYPE;
        } else {
            type = STRING_TYPE;
        }
        return type;
    }

    private static Map<String, String> getAttributeNameToSection(ServiceSchema schema) {
        Map<String, String> result = new LinkedHashMap<>();

        String serviceSectionFilename = schema.getName();
        if (serviceSectionFilename == null || serviceSectionFilename.equals("serverconfig")) {
            serviceSectionFilename = schema.getServiceName();
        }
        serviceSectionFilename = serviceSectionFilename + ".section.properties";

        InputStream inputStream = SmsJsonSchema.class.getClassLoader().getResourceAsStream(serviceSectionFilename);

        if (inputStream != null) {
            String line;
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            try {
                while ((line = reader.readLine()) != null) {
                    if (!(line.matches("^\\#.*") || line.isEmpty())) {
                        String[] attributeValue = line.split("=");
                        final String sectionName = attributeValue[0];
                        result.put(attributeValue[1], sectionName);
                    }
                }
            } catch (IOException e) {
                if (debug.errorEnabled()) {
                    debug.error("Error reading section properties file", e);
                }
            }
        }
        return result;
    }



    private static String realmFor(Context context) {
        return context.containsContext(RealmContext.class) ?
                context.asContext(RealmContext.class).getResolvedRealm() : null;
    }
}
