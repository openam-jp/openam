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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2026 OSSTech Corporation
 */

package org.forgerock.openam.core.rest.sms;

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.util.LinkedHashMap;
import javax.inject.Inject;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.identity.common.configuration.MapValueParser;
import com.sun.identity.idm.IdConstants;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.encode.Base64;
import com.sun.identity.shared.xml.XMLUtils;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.AttributeSchema.Syntax;
import com.sun.identity.sm.InvalidAttributeValueException;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceSchema;

import jp.co.osstech.openam.core.rest.sms.AttributeSchemaFilter;

import org.apache.commons.lang.StringUtils;
import org.forgerock.guava.common.collect.BiMap;
import org.forgerock.guava.common.collect.HashBiMap;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.JsonException;
import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.util.Pair;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * A class to convert service configurations between XML and JSON
 * @since 13.0.0
 */
public class SmsJsonConverter {
    private static final Pattern orderedListPattern = Pattern.compile("(\\s*\\[\\s*\\d++\\s*\\]\\s*=.*)");

    private final MapValueParser nameValueParser = new MapValueParser();
    private final Debug debug = Debug.getInstance("SmsJsonConverter");
    private final Map<String, AttributeSchemaConverter> attributeSchemaConverters = new HashMap<String, AttributeSchemaConverter>();
    protected final ServiceSchema schema;

    private BiMap<String, String> attributeNameToResourceName;
    private BiMap<String, String> resourceNameToAttributeName;
    private Map<String, String> attributeNameToSection;
    private List<String> hiddenAttributeNames;
    protected boolean initialised = false;

    @Inject
    public SmsJsonConverter(ServiceSchema schema) {
        this.schema = schema;
    }

    protected synchronized void init() {
        if (initialised) {
            return;
        }
        attributeNameToResourceName = getAttributeNameToResourceName(schema);
        hiddenAttributeNames = getHiddenAttributeNames();

        for (Object attributeName : schema.getAttributeSchemaNames()) {
            AttributeSchemaConverter attributeSchemaConverter;

            final AttributeSchema attributeSchema = this.schema.getAttributeSchema((String) attributeName);
            final AttributeSchema.Syntax syntax = attributeSchema.getSyntax();

            attributeSchemaConverter = getAttributeSchemaValue(syntax);

            final String resourceName = attributeSchema.getResourceName();
            if (resourceName == null) {
                attributeSchemaConverters.put((String) attributeName, attributeSchemaConverter);
            } else {
                attributeSchemaConverters.put(resourceName, attributeSchemaConverter);
            }
        }

        resourceNameToAttributeName = attributeNameToResourceName.inverse();
        attributeNameToSection = getAttributeNameToSection();

        initialised = true;
    }

    protected AttributeSchemaConverter getAttributeSchemaValue(AttributeSchema.Syntax syntax) {
        AttributeSchemaConverter attributeSchemaConverter;
        if (isBoolean(syntax)) {
            attributeSchemaConverter = new BooleanAttributeSchemaValue();
        } else if (isDouble(syntax)) {
            attributeSchemaConverter = new DoubleAttributeSchemaValue();
        } else if (isInteger(syntax)) {
            attributeSchemaConverter = new IntegerAttributeSchemaValue();
        } else if (isScript(syntax)) {
            attributeSchemaConverter = new ScriptAttributeSchemaValue();
        } else if (isPassword(syntax)) {
            attributeSchemaConverter = new PasswordAttributeSchemaValue();
        } else {
            attributeSchemaConverter = new StringAttributeSchemaValue();
        }
        return attributeSchemaConverter;
    }

    /**
     * Will validate the Map representation of the service configuration against the global serviceSchema and return a
     * corresponding JSON representation
     *
     * @param attributeValuePairs The schema attribute values.
     * @param validate Should the attributes be validated.
     * @return Json representation of attributeValuePairs
     */
    public JsonValue toJson(Map<String, Set<String>> attributeValuePairs, boolean validate) {
        return toJson(null, attributeValuePairs, validate);
    }

    /**
     * Will validate the Map representation of the service configuration against the serviceSchema and return a
     * corresponding JSON representation
     *
     * @param attributeValuePairs The schema attribute values.
     * @param validate Should the attributes be validated.
     * @param parentJson The {@link JsonValue} to which the attributes should be added.
     * @return Json representation of attributeValuePairs
     */
    public JsonValue toJson(Map<String, Set<String>> attributeValuePairs, boolean validate, JsonValue parentJson) {
        return toJson(null, attributeValuePairs, validate, parentJson);
    }

    /**
     * Will validate the Map representation of the service configuration against the serviceSchema and return a
     * corresponding JSON representation
     *
     * @param realm The realm, or null if global.
     * @param attributeValuePairs The schema attribute values.
     * @param validate Should the attributes be validated.
     * @return Json representation of attributeValuePairs
     */
    public JsonValue toJson(String realm, Map<String, Set<String>> attributeValuePairs, boolean validate) {
        return toJson(realm, attributeValuePairs, validate, json(object()));
    }

    /**
     * Will validate the Map representation of the service configuration against the serviceSchema and return a
     * corresponding JSON representation
     *
     * @param realm The realm, or null if global.
     * @param attributeValuePairs The schema attribute values.
     * @param validate Should the attributes be validated.
     * @param parentJson The {@link JsonValue} to which the attributes should be added.
     * @return Json representation of attributeValuePairs
     */
    public JsonValue toJson(String realm, Map<String, Set<String>> attributeValuePairs, boolean validate,
            JsonValue parentJson) {
        return toJson(realm, attributeValuePairs, validate, false, null, null, parentJson);
    }

    /**
     * Will validate the Map representation of the service configuration against the serviceSchema and return a
     * corresponding JSON representation
     *
     * @param realm The realm, or null if global.
     * @param attributeValuePairs The schema attribute values.
     * @param validate Should the attributes be validated.
     * @param inheritable whether to inherit default or group values
     * @param nonInheritableAttributes The attributes excluded from inheritance
     * @param inheritedAttributes The inherited attributes
     * @param parentJson The {@link JsonValue} to which the attributes should be added.
     * @return Json representation of attributeValuePairs
     */
    public JsonValue toJson(String realm, Map<String, Set<String>> attributeValuePairs, boolean validate,
            boolean inheritable, Set<String> nonInheritableAttributes, Set<String> inheritedAttributes,
            JsonValue parentJson) {

        if (!initialised) {
            init();
        }

        boolean validAttributes = true;
        if (validate) {
            try {
                if (realm == null) {
                    validAttributes = schema.validateAttributes(attributeValuePairs);
                } else {
                    validAttributes = schema.validateAttributes(attributeValuePairs, realm);
                }
            } catch (SMSException e) {
                debug.error("schema validation threw an exception while validating the attributes: realm=" + realm +
                        " attributes: " + attributeValuePairs, e);
                throw new JsonException("Unable to validate attributes", e);
            }
        }

        if (validAttributes) {
            for (String attributeName : attributeValuePairs.keySet()) {
                String jsonResourceName = attributeNameToResourceName.get(attributeName);

                String name;
                if (jsonResourceName != null) {
                    name = jsonResourceName;
                } else {
                    name = attributeName;
                }

                AttributeSchema attributeSchema = schema.getAttributeSchema(attributeName);

                if (shouldBeIgnored(attributeName)) {
                    continue;
                }

                AttributeSchema.Type type = attributeSchema.getType();
                final Set<String> object = attributeValuePairs.get(attributeName);

                Object jsonAttributeValue = null;

                if (type == null) {
                    throw new JsonException("Type not defined.");
                }

                AttributeSchemaConverter attributeSchemaConverter = attributeSchemaConverters.get(name);

                if (isASingleValue(type)) {
                    if (!object.isEmpty()) {
                        jsonAttributeValue = attributeSchemaConverter.toJson(object.iterator().next());
                    }
                } else if (containsMultipleValues(type)) {
                    if (isAMap(attributeSchema.getUIType())) {
                        Map<String, Object> map = new HashMap<String, Object>();
                        boolean isGlobalMapList =
                                AttributeSchema.UIType.GLOBALMAPLIST.equals(attributeSchema.getUIType());

                        Iterator<String> itr = object.iterator();
                        while (itr.hasNext()) {
                            String value = itr.next();
                            Pair<String, String> entry = nameValueParser.parse(value);
                            if (entry != null) {
                                map.put(entry.getFirst(), attributeSchemaConverter.toJson(entry.getSecond()));
                            } else if (isGlobalMapList) {
                                if (!"[]=".equals(value)) {
                                    // The global setting key is the empty string
                                    map.put("", value);
                                }
                            }
                        }
                        jsonAttributeValue = map;
                    } else if (isOrderedListConfiguration(attributeSchema.getUIType(),
                            attributeSchema.getSyntax(), object)) {
                        Set<String> sorted = new TreeSet<String>(new Comparator<String>() {
                            @Override
                            public int compare(String s1, String s2) {
                                int idx1 = getIndex(s1);
                                int idx2 = getIndex(s2);
                                if (idx1 == idx2) {
                                    return 0;
                                }
                                return (idx1 < idx2) ? -1 : 1;
                            }
                            private int getIndex(String str) {
                                int idx = str.indexOf("]");
                                return Integer.parseInt(str.substring(1, idx));
                            }
                        });
                        sorted.addAll(object);

                        if (sorted.size() == 1) {
                            String tmp = (String)sorted.iterator().next();
                            if (tmp.equals("[0]=")) {
                                sorted.clear();
                            }
                        }

                        List<Object> list = new ArrayList<Object>();
                        for (String value : sorted) {
                            int idx = value.indexOf(']');
                            idx = value.indexOf('=', idx);
                            list.add(value.substring(idx+1).trim());
                        }
                        jsonAttributeValue = list;
                    } else {
                        List<Object> list = new ArrayList<Object>();

                        Iterator<String> itr = object.iterator();
                        while (itr.hasNext()) {
                            list.add(attributeSchemaConverter.toJson(itr.next()));
                        }
                        jsonAttributeValue = list;
                    }
                }

                boolean addInherited = inheritable && nonInheritableAttributes != null
                        && !nonInheritableAttributes.contains(attributeName);
                String sectionName = attributeNameToSection.get(attributeName);
                if (addInherited) {
                    if (sectionName != null) {
                        parentJson.putPermissive(new JsonPointer("/" + sectionName + "/" + name + "/inherited"),
                                inheritedAttributes.contains(attributeName));
                        parentJson.putPermissive(new JsonPointer("/" + sectionName + "/" + name + "/value"), jsonAttributeValue);
                    } else {
                        parentJson.putPermissive(new JsonPointer("/" + name + "/inherited"),
                                inheritedAttributes.contains(attributeName));
                        parentJson.putPermissive(new JsonPointer("/" + name + "/value"), jsonAttributeValue);
                    }
                } else {
                    if (sectionName != null) {
                        parentJson.putPermissive(new JsonPointer("/" + sectionName + "/" + name), jsonAttributeValue);
                    } else {
                        parentJson.put(name, jsonAttributeValue);
                    }
                }
            }
        } else {
            throw new JsonException("Invalid attributes");
        }
        return parentJson;
    }

    private boolean isAMap(AttributeSchema.UIType type) {
        return AttributeSchema.UIType.MAPLIST.equals(type)
                || AttributeSchema.UIType.GLOBALMAPLIST.equals(type);
    }

    private boolean isOrderedListConfiguration(AttributeSchema.UIType type, Syntax syntax, Set<String> values) {
        if ((AttributeSchema.UIType.ORDEREDLIST.equals(type)
                || AttributeSchema.UIType.UNORDEREDLIST.equals(type))
                && AttributeSchema.Syntax.STRING.equals(syntax)) {
            // If even one value does not have a prefix, it will not be treated as orderedlist
            boolean valid = true;
            for (String value : values) {
                if (value.length() > 0) {
                    Matcher m = orderedListPattern.matcher(value);
                    valid &= m.matches();
                } else {
                    return false;
                }
            }
            return valid;
        }
        return false;
    }

    private boolean containsMultipleValues(AttributeSchema.Type type) {
        return type.equals(AttributeSchema.Type.LIST) || type.equals(AttributeSchema.Type.MULTIPLE_CHOICE);
    }

    private boolean isASingleValue(AttributeSchema.Type type) {
        return type.equals(AttributeSchema.Type.SINGLE) || type.equals(AttributeSchema.Type.SIGNATURE) || type
                .equals(AttributeSchema.Type.VALIDATOR) || type.equals(AttributeSchema.Type
                .SINGLE_CHOICE);
    }

    protected boolean isDate(AttributeSchema.Syntax syntax) {
        return syntax.equals(AttributeSchema.Syntax.DATE);
    }

    protected boolean isBoolean(AttributeSchema.Syntax syntax) {
        return syntax.equals(AttributeSchema.Syntax.BOOLEAN);
    }

    protected boolean isInteger(AttributeSchema.Syntax syntax) {
        return syntax.equals(AttributeSchema.Syntax.NUMBER) || syntax.equals(AttributeSchema.Syntax.NUMBER_RANGE)
                || syntax.equals(AttributeSchema.Syntax.NUMERIC) || syntax.equals(AttributeSchema.Syntax.PERCENT);
    }

    protected boolean isDouble(AttributeSchema.Syntax syntax) {
        return syntax.equals(AttributeSchema.Syntax.DECIMAL) || syntax.equals(AttributeSchema.Syntax
                .DECIMAL_NUMBER) || syntax.equals(AttributeSchema.Syntax.DECIMAL_RANGE);
    }

    protected boolean isScript(AttributeSchema.Syntax syntax) {
        return syntax.equals(AttributeSchema.Syntax.SCRIPT);
    }

    protected boolean isPassword(AttributeSchema.Syntax syntax) {
        return syntax.equals(AttributeSchema.Syntax.PASSWORD);
    }

    /**
     * Will validate the Json representation of the service configuration against the global serviceSchema,
     * and return a corresponding Map representation.
     *
     * @param jsonValue The request body.
     * @return Map representation of jsonValue
     */
    public Map<String, Set<String>> fromJson(JsonValue jsonValue) throws JsonException, BadRequestException {
        return fromJson(null, jsonValue);
    }

    /**
     * Will validate the Json representation of the service configuration against the serviceSchema for a realm,
     * and return a corresponding Map representation.
     *
     * @param realm The realm, or null if global.
     * @param jsonValue The request body.
     * @return Map representation of jsonValue
     */
    public Map<String, Set<String>> fromJson(String realm, JsonValue jsonValue) throws JsonException, BadRequestException {
        return fromJson(realm, jsonValue, false, null, null, null);
    }

    /**
     * Will validate the Json representation of the service configuration against the serviceSchema for a realm,
     * and return a corresponding Map representation.
     *
     * @param realm The realm, or null if global.
     * @param jsonValue The request body.
     * @param inheritable whether to inherit default or group values
     * @param nonInheritableAttributes The attributes excluded from inheritance
     * @param inheritedAttributes The inherited attributes
     * @param nonInheritedAttributes The non-inherited attributes
     * @return Map representation of jsonValue
     */
    public Map<String, Set<String>> fromJson(String realm, JsonValue jsonValue, boolean inheritable,
            Set<String> nonInheritableAttributes, Set<String> inheritedAttributes, Set<String> nonInheritedAttributes)
                    throws JsonException, BadRequestException {
        return fromJson(realm, jsonValue, inheritable, nonInheritableAttributes, inheritedAttributes, nonInheritedAttributes, null);
    }

    /**
     * Will validate the Json representation of the service configuration against the serviceSchema for a realm,
     * and return a corresponding Map representation.
     *
     * @param realm The realm, or null if global.
     * @param jsonValue The request body.
     * @param inheritable whether to inherit default or group values
     * @param nonInheritableAttributes The attributes excluded from inheritance
     * @param inheritedAttributes The inherited attributes
     * @param nonInheritedAttributes The non-inherited attributes
     * @param filter the filter to optimize for the service
     * @return Map representation of jsonValue
     */
    public Map<String, Set<String>> fromJson(String realm, JsonValue jsonValue, boolean inheritable,
            Set<String> nonInheritableAttributes, Set<String> inheritedAttributes, Set<String> nonInheritedAttributes,
            AttributeSchemaFilter filter)
                    throws JsonException, BadRequestException {
        if (!initialised) {
            init();
        }

        Map<String, Set<String>> result = new HashMap<>();
        if (jsonValue == null || jsonValue.isNull()) {
            return result;
        }
        Map<String, Object> translatedAttributeValuePairs = getTranslatedAttributeValuePairs(jsonValue.asMap());

        for (String attributeName : translatedAttributeValuePairs.keySet()) {

            // Ignore _id field used to name resource when creating
            if (ResourceResponse.FIELD_CONTENT_ID.equals(attributeName)) {
                continue;
            }

            if (shouldBeIgnored(attributeName)) {
                continue;
            }

            if(shouldNotBeUpdated(attributeName, filter)) {
                throw new BadRequestException("Invalid attribute, '" + attributeName + "', specified");
            }


            Object attributeValue = translatedAttributeValuePairs.get(attributeName);
            Set<String> value = new HashSet<>();

            boolean inheritableAttribute = inheritable && nonInheritableAttributes != null
                    && !nonInheritableAttributes.contains(attributeName);
            if (inheritableAttribute) {
                if (attributeValue instanceof HashMap) {
                    final HashMap<String, Object> attributeMap = (HashMap<String, Object>) attributeValue;
                    if (attributeMap.containsKey("inherited")) {
                        Object o = attributeMap.get("inherited");
                        if (o instanceof Boolean && (Boolean)o) {
                            inheritedAttributes.add(attributeName);
                        } else {
                            nonInheritedAttributes.add(attributeName);
                        }
                        if (!attributeMap.containsKey("value")) {
                            // If the attribute has only `inherited` field, do not set a value in the return value
                            continue;
                        }
                        attributeValue = attributeMap.get("value");
                    }
                }
            } else {
                // If inheritance is not supported and the `inherited` field is specified, throw exception
                if (attributeValue instanceof HashMap) {
                    final HashMap<String, Object> attributeMap = (HashMap<String, Object>) attributeValue;
                    if (attributeMap.containsKey("inherited")) {
                        throw new BadRequestException("Invalid attribute value syntax: '" + attributeName + "'");
                    }
                }
            }

            if (attributeValue instanceof HashMap) {
                final HashMap<String, Object> attributeMap = (HashMap<String, Object>) attributeValue;
                AttributeSchema attributeSchema = schema.getAttributeSchema(attributeName);
                boolean isGlobalMapList =
                        AttributeSchema.UIType.GLOBALMAPLIST.equals(attributeSchema.getUIType());
                for (String name : attributeMap.keySet()) {
                    if (name.isEmpty() && isGlobalMapList) {
                        value.add(convertJsonToString(attributeName, attributeMap.get(name)));
                    } else {
                        value.add("[" + name + "]=" + convertJsonToString(attributeName, attributeMap.get(name)));
                    }
                }
            } else if (attributeValue instanceof List) {
                List<Object> attributeArray = (ArrayList<Object>) attributeValue;
                AttributeSchema attributeSchema = schema.getAttributeSchema(attributeName);
                if ((AttributeSchema.UIType.ORDEREDLIST.equals(attributeSchema.getUIType())
                        || AttributeSchema.UIType.UNORDEREDLIST.equals(attributeSchema.getUIType()))
                        && AttributeSchema.Syntax.STRING.equals(attributeSchema.getSyntax())) {
                    int index = 0;
                    for (Object val : attributeArray) {
                        value.add("[" + index++ + "]=" + convertJsonToString(attributeName, val));
                    }
                } else {
                    for (Object val : attributeArray) {
                        value.add(convertJsonToString(attributeName, val));
                    }
                }
            } else if (attributeValue != null) {
                value.add(convertJsonToString(attributeName, attributeValue));
            }

            // For AgentService
            if (value.isEmpty() && schema.getServiceName().equals(IdConstants.AGENT_SERVICE)) {
                // AgentService requires a special value as the initial value
                AttributeSchema.UIType uiType = schema.getAttributeSchema(attributeName).getUIType();
                if (AttributeSchema.UIType.ORDEREDLIST.equals(uiType)
                        || AttributeSchema.UIType.UNORDEREDLIST.equals(uiType)) {
                    value.add("[0]=");
                } else if (AttributeSchema.UIType.MAPLIST.equals(uiType)
                        || AttributeSchema.UIType.GLOBALMAPLIST.equals(uiType)) {
                    value.add("[]=");
                }
            }

            if (!value.isEmpty() || !isPassword(schema.getAttributeSchema(attributeName).getSyntax())) {
                result.put(attributeName, value);
            }
        }

        try {
            if (result.isEmpty() ||
                    (realm == null && schema.validateAttributes(result)) ||
                    (realm != null && schema.validateAttributes(result, realm))) {
                return result;
            } else {
                throw new JsonException("Invalid attributes");
            }
        } catch (InvalidAttributeValueException e) {
            throw new BadRequestException(e.getLocalizedMessage(), e);
        } catch (SMSException e) {
            throw new JsonException("Unable to validate attributes", e);
        }
    }

    private boolean shouldBeIgnored(String attributeName) {
        final AttributeSchema attributeSchema = schema.getAttributeSchema(attributeName);
        return (attributeSchema != null && StringUtils.isBlank(attributeSchema.getI18NKey())) || attributeName.equals
                ("_type") || hiddenAttributeNames.contains(attributeName);
    }

    private boolean shouldNotBeUpdated(String attributeName, AttributeSchemaFilter filter) {
        final AttributeSchema attributeSchema = schema.getAttributeSchema(attributeName);
        return attributeSchema == null || hiddenAttributeNames.contains(attributeName)
                || ( filter != null && !filter.isTarget(attributeSchema));
    }

    private AttributeSchemaConverter getAttributeConverter(String attributeName) {
        return attributeNameToResourceName.get(attributeName) == null ?
                attributeSchemaConverters.get(attributeName) : attributeSchemaConverters.get(attributeNameToResourceName.get(attributeName));
    }

    /**
     * Checks each attribute name in the json to see whether it is actually a resource name and therefore needs to be
     * translated back to the original attribute name
     *
     * @param attributeValuePairs The untranslated list of attribute names to values
     * @return The attribute name to value pairs with all their original attribute names
     */
    protected Map<String, Object> getTranslatedAttributeValuePairs(Map<String, Object> attributeValuePairs) {
        Map<String, Object> translatedAttributeValuePairs = new HashMap<String, Object>();

        for (String attributeName : attributeValuePairs.keySet()) {
            if (!isASectionName(attributeName)) {
                String translatedAttributeName = resourceNameToAttributeName.get(attributeName);

                if (translatedAttributeName != null) {
                    translatedAttributeValuePairs.put(translatedAttributeName, attributeValuePairs.get(attributeName));
                } else {
                    translatedAttributeValuePairs.put(attributeName, attributeValuePairs.get(attributeName));
                }
            } else {
                translatedAttributeValuePairs.putAll(getTranslatedAttributeValuePairs((Map<String, Object>)
                        attributeValuePairs.get(attributeName)));
            }
        }
        return translatedAttributeValuePairs;
    }

    private boolean isASectionName(String attributeName) {
        return attributeNameToSection.containsValue(attributeName);
    }

    protected List<String> getHiddenAttributeNames() {
        ArrayList<String> hiddenAttributeNames = null;

        try {
            InputStream resource = getClass().getClassLoader().getResourceAsStream("amConsoleConfig.xml");
            Document doc = XMLUtils.getSafeDocumentBuilder(false).parse(resource);
            NodeList nodes = (NodeList) XPathFactory.newInstance().newXPath().evaluate(
                    "//consoleconfig/servicesconfig/consoleservice/@realmEnableHideAttrName", doc,
                    XPathConstants.NODESET);
            String rawList = nodes.item(0).getNodeValue();
            hiddenAttributeNames = new ArrayList<>(Arrays.asList(rawList.split(",")));
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (XPathExpressionException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return hiddenAttributeNames;
    }

    protected Map<String, String> getAttributeNameToSection() {
        Map<String, String> result = new LinkedHashMap();
        String serviceSectionFilename = schema.getName() != null ? schema.getName() : schema.getServiceName();
        serviceSectionFilename = serviceSectionFilename + ".section.properties";

        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(serviceSectionFilename);

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

    private BiMap<String, String> getAttributeNameToResourceName(ServiceSchema schema) {
        HashBiMap<String, String> result = HashBiMap.create();

        for (String attributeName : (Set<String>) schema.getAttributeSchemaNames()) {
            final String resourceName = schema.getAttributeSchema(attributeName).getResourceName();
            if (resourceName != null) {
                result.put(attributeName, resourceName);
            }
        }
        return result;
    }

    protected String convertJsonToString(String attributeName, Object value) throws BadRequestException {
        AttributeSchemaConverter converter = getAttributeConverter(attributeName);
        try {
            return converter.fromJson(value);
        } catch (ClassCastException cce) {
            throw new BadRequestException("Invalid attribute value syntax: '" + value + "'", cce);
        }
    }

    protected static interface AttributeSchemaConverter {
        Object toJson(String value);
        String fromJson(Object json);
    }

    protected static class StringAttributeSchemaValue implements AttributeSchemaConverter {
        public StringAttributeSchemaValue() {}

        @Override
        public Object toJson(String value) {
            return value;
        }

        @Override
        public String fromJson(Object json) {
            return (String) json;
        }
    }

    protected static class PasswordAttributeSchemaValue implements AttributeSchemaConverter {
        public PasswordAttributeSchemaValue() {}

        @Override
        public Object toJson(String value) {
            return null;
        }

        @Override
        public String fromJson(Object json) {
            return (String) json;
        }
    }

    protected class BooleanAttributeSchemaValue implements AttributeSchemaConverter {
        public BooleanAttributeSchemaValue() {}

        @Override
        public Object toJson(String value) {
            return Boolean.parseBoolean(value);
        }

        @Override
        public String fromJson(Object json) {
            return Boolean.toString((Boolean) json);
        }
    }

    protected static class DoubleAttributeSchemaValue implements AttributeSchemaConverter {
        public DoubleAttributeSchemaValue() {}

        @Override
        public Object toJson(String value) {
            return Double.parseDouble(value);
        }

        @Override
        public String fromJson(Object json) {
            return Double.toString((Double) json);
        }
    }

    protected static class IntegerAttributeSchemaValue implements AttributeSchemaConverter {
        public IntegerAttributeSchemaValue() {}

        @Override
        public Object toJson(String value) {
            return Integer.parseInt(value);
        }

        @Override
        public String fromJson(Object json) {
            return Integer.toString((Integer) json);
        }
    }

    protected static class ScriptAttributeSchemaValue implements AttributeSchemaConverter {
        public ScriptAttributeSchemaValue() {}

        @Override
        public Object toJson(String value) {
            try {
                return Base64.encode(value.getBytes("UTF-8"));
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException("Script encoding failed", e);
            }
        }

        @Override
        public String fromJson(Object json) {
            String decodedValue = Base64.decodeAsUTF8String((String)json);
            return decodedValue == null ? "" : decodedValue;

        }
    }
}
