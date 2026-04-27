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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class IDPAttributeConsentConfigTest {

    private IDPAttributeConsentConfig attributes;

    @BeforeMethod
    public void setup() {
        attributes = new IDPAttributeConsentConfig(Arrays.asList(
                "ID",
                "phoneNumber|Telephone Number",
                "mail|Mail Address DEFAULT",
                "mail|en|Mail Address EN",
                "mail|ja|Mail Address JA"));
    }

    @Test
    public void requireConsentIfMatchConfig() {
        assertTrue(attributes.consentRequired("ID"));
        assertTrue(attributes.consentRequired("phoneNumber"));
        assertTrue(attributes.consentRequired("mail"));
    }

    @Test
    public void doNotRequireConsentIfNotMatchConfig() {
        assertFalse(attributes.consentRequired("address"));
    }

    @Test
    public void returnLocalizedNameIfLanguageMatch() {
        Locale locale = Locale.forLanguageTag("en");
        Map<String, List<String>> attributesInAssertion = new HashMap<>();
        attributesInAssertion.put("mail", Arrays.asList("dummy"));

        assertEquals(attributes.getConsentRequiredAttributes(attributesInAssertion, locale).get(0).displayName(),
                "Mail Address EN");
    }

    @Test
    public void returnDisplayNameIfLanguageDoesNotMatch() {
        Locale locale = Locale.forLanguageTag("fr");
        Map<String, List<String>> attributesInAssertion = new HashMap<>();
        attributesInAssertion.put("mail", Arrays.asList("dummy"));

        assertEquals(attributes.getConsentRequiredAttributes(attributesInAssertion, locale).get(0).displayName(),
                "Mail Address DEFAULT");
    }

    @Test
    public void returnDisplayNameIfLanguageIsNotSet() {
        Locale locale = Locale.forLanguageTag("en");
        Map<String, List<String>> attributesInAssertion = new HashMap<>();
        attributesInAssertion.put("phoneNumber", Arrays.asList("dummy"));

        assertEquals(attributes.getConsentRequiredAttributes(attributesInAssertion, locale).get(0).displayName(),
                "Telephone Number");
    }

    @Test
    public void returnAttributeNameIfDisplayNameIsNotSet() {
        Locale locale = Locale.forLanguageTag("en");
        Map<String, List<String>> attributesInAssertion = new HashMap<>();
        attributesInAssertion.put("ID", Arrays.asList("dummy"));

        assertEquals(attributes.getConsentRequiredAttributes(attributesInAssertion, locale).get(0).displayName(), "ID");
    }

    @Test
    public void searchByGeneralLanguageIfLanguageDoesNotMatch() {
        Locale locale = Locale.forLanguageTag("en-US");
        Map<String, List<String>> attributesInAssertion = new HashMap<>();
        attributesInAssertion.put("mail", Arrays.asList("dummy"));

        assertEquals(attributes.getConsentRequiredAttributes(attributesInAssertion, locale).get(0).displayName(),
                "Mail Address EN");
    }

    @Test
    public void returnAttributesInOrder() {
        attributes = new IDPAttributeConsentConfig(Arrays.asList(
                "attr1", "attr2", "attr3"));

        Locale locale = Locale.forLanguageTag("en");
        Map<String, List<String>> attributesInAssertion = new HashMap<>();
        attributesInAssertion.put("attr1", Arrays.asList("dummy"));
        attributesInAssertion.put("attr2", Arrays.asList("dummy"));
        attributesInAssertion.put("attr3", Arrays.asList("dummy"));

        List<ConsentRequiredAttribute> result = attributes.getConsentRequiredAttributes(attributesInAssertion, locale);
        assertEquals(result.get(0).displayName(), "attr1");
        assertEquals(result.get(1).displayName(), "attr2");
        assertEquals(result.get(2).displayName(), "attr3");
    }
}
