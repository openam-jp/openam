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
package jp.co.osstech.openam.saml2.consent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The class <code>IDPAttributeConsentConfig<code> represents the configuration
 * of the IdP for attribute consent step.
 */
class IDPAttributeConsentConfig {

    private static final String EMPTY_LANGUAGE_KEY = "empty";

    // <attributeName, <language, displayName>>
    private Map<String, Map<String, String>> attributes;

    /**
     * Constructor.
     *
     * @param config List of String represents attributes configuration. Each String
     *               must be ATTRIBUTE_NAME|LANGUAGE|DISPLAY_NAME or
     *               ATTRIBUTE_NAME|DISPLAY_NAME or ATTRIBUTE_NAME.
     */
    IDPAttributeConsentConfig(List<String> config) {
        attributes = new LinkedHashMap<>();
        if (config == null) {
            return;
        }
        for (String line : config) {
            registerAttribute(line);
        }
    }

    /**
     * Check whether the IdP require consent for the given attribute.
     *
     * @param attributeName Attribute name in assertion.
     * @return True if IdP require consent for the attribute.
     */
    boolean consentRequired(String attributeName) {
        return attributes.containsKey(attributeName);
    }

    /**
     * Extract consent required attributes and convert attribute names.
     *
     * @param attributes Attributes in assertion.
     * @param locale     Request locale
     * @return Consent required attributes which converted for given locale.
     */
    List<ConsentRequiredAttribute> getConsentRequiredAttributes(Map<String, List<String>> attributes, Locale locale) {
        Map<String, List<String>> consentRequiredAttributes = extractConsentRequiredAttributes(attributes);
        Map<String, List<String>> sorted = sort(consentRequiredAttributes);
        List<ConsentRequiredAttribute> translated = translate(sorted, locale);
        return translated;
    }

    private void registerAttribute(String line) {
        String attributeName, language, displayName;
        String[] splitted = line.split("\\|");
        if (splitted.length == 0) {
            return;
        } else if (splitted.length == 1) {
            attributeName = splitted[0];
            language = EMPTY_LANGUAGE_KEY;
            displayName = null;
        } else if (splitted.length == 2) {
            attributeName = splitted[0];
            language = EMPTY_LANGUAGE_KEY;
            displayName = splitted[1];
        } else {
            attributeName = splitted[0];
            language = splitted[1];
            displayName = splitted[2];
        }

        if (attributes.containsKey(attributeName)) {
            attributes.get(attributeName).put(language, displayName);
        } else {
            Map<String, String> newEntry = new HashMap<>();
            newEntry.put(language, displayName);
            attributes.put(attributeName, newEntry);
        }
    }

    private Map<String, List<String>> extractConsentRequiredAttributes(Map<String, List<String>> attributes) {
        Map<String, List<String>> answer = new HashMap<>();
        for (String attributeName : attributes.keySet()) {
            if (consentRequired(attributeName)) {
                List<String> attributeValue = attributes.get(attributeName);
                answer.put(attributeName, attributeValue);
            }
        }
        return answer;
    }

    private Map<String, List<String>> sort(Map<String, List<String>> attributes) {
        Map<String, List<String>> answer = new LinkedHashMap<>();
        for (String attributeName : this.attributes.keySet()) {
            if (attributes.keySet().contains(attributeName)) {
                List<String> attributeValue = attributes.get(attributeName);
                answer.put(attributeName, attributeValue);
            }
        }
        return answer;
    }

    private List<ConsentRequiredAttribute> translate(Map<String, List<String>> attributes, Locale locale) {
        List<ConsentRequiredAttribute> translated = new ArrayList<>();

        for (String attributeName : attributes.keySet()) {
            String translatedAttributeName = translate(attributeName, locale);
            List<String> attributeValue = attributes.get(attributeName);
            ConsentRequiredAttribute consentRequiredAttributes = new ConsentRequiredAttribute(attributeName,
                    translatedAttributeName, attributeValue);
            translated.add(consentRequiredAttributes);
        }
        return translated;
    }

    private String translate(String attributeName, Locale locale) {
        List<String> splittedLocale = splitLocale(locale);
        for (String localeStr : splittedLocale) {
            String localizedName = attributes.get(attributeName).get(localeStr);
            if (localizedName != null) {
                return localizedName;
            }
        }

        String displayName = attributes.get(attributeName).get(EMPTY_LANGUAGE_KEY);
        if (displayName != null) {
            return displayName;
        }

        return attributeName;
    }

    private List<String> splitLocale(Locale locale) {
        List<String> answer = new ArrayList<>();

        String localeStr = locale.toString();
        answer.add(localeStr);
        while (localeStr.lastIndexOf("_") != -1) {
            int index = localeStr.lastIndexOf("_");
            localeStr = localeStr.substring(0, index);
            answer.add(localeStr);
        }

        return answer;
    }

}
