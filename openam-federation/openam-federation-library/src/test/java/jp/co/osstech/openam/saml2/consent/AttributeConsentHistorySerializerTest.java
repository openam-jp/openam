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

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jp.co.osstech.openam.saml2.consent.AttributeConsent.ConsentType;

public class AttributeConsentHistorySerializerTest {

    private static ObjectMapper mapper;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static String signingSecret;

    private static final String REALM = "/testrealm";
    private static final String IDP = "https://idp.example.com";
    private static final String SP = "https://sp.example.com";
    private static final String USER = "testuser";

    @BeforeClass
    public void setupObjectMapper() throws Exception {
        mapper = new ObjectMapper();
        mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        signingSecret = "SecretPhraseUsedForSigningJWT";
    }

    @Test
    public void canSerializeAndDeserializeHistory() throws Exception {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM, IDP, SP, USER, new HashSet<String>(Arrays.asList("mail", "phoneNumber")),
                ConsentType.ASK_IF_CHANGE);

        AttributeConsentHistorySerializer serializer = new AttributeConsentHistorySerializer(publicKey, privateKey,
                signingSecret);
        String serialized = serializer.serializeAndEncrypt(history);
        AttributeConsentHistory deserialized = serializer.decryptAndDeserialize(serialized);

        assertFalse(deserialized.consentRequired(REALM, IDP, SP, USER,
                new HashSet<String>(Arrays.asList("mail", "phoneNumber"))));
        assertTrue(deserialized.consentRequired(REALM, IDP, SP, USER,
                new HashSet<String>(Arrays.asList("ID"))));
    }

    @Test(expectedExceptions = { JsonParseException.class })
    public void historyIsEncrypted() throws Exception {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM, IDP, SP, USER, new HashSet<String>(Arrays.asList("mail", "phoneNumber")),
                ConsentType.ASK_IF_CHANGE);

        AttributeConsentHistorySerializer serializer = new AttributeConsentHistorySerializer(publicKey, privateKey,
                signingSecret);
        String serialized = serializer.serializeAndEncrypt(history);
        mapper.readValue(serialized, AttributeConsentHistory.class);
        // If the history is successfully deserialized, It means the history is not
        // encrypted.
        fail();
    }

    @Test
    public void invalidSignatureIsIgnoredAndReturnEmptyHistory() throws Exception {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM, IDP, SP, USER, new HashSet<String>(Arrays.asList("mail", "phoneNumber")),
                ConsentType.ASK_NEVER);
        AttributeConsentHistorySerializer invalidSerializer = new AttributeConsentHistorySerializer(publicKey,
                privateKey,
                "InvalidSigningSecret");

        String serialized = invalidSerializer.serializeAndEncrypt(history);

        AttributeConsentHistorySerializer serializer = new AttributeConsentHistorySerializer(publicKey, privateKey,
                signingSecret);
        AttributeConsentHistory deserialized = serializer.decryptAndDeserialize(serialized);
        assertTrue(deserialized.consentRequired(REALM, IDP, SP, USER,
                new HashSet<String>(Arrays.asList("mail", "phoneNumber"))));
    }
}
