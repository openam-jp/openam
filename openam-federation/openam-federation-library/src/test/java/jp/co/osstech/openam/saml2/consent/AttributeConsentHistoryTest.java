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

import java.util.Arrays;
import java.util.HashSet;

import org.testng.annotations.Test;

import jp.co.osstech.openam.saml2.consent.AttributeConsent.ConsentType;

public class AttributeConsentHistoryTest {

    private static final String REALM1 = "/testrealm1";
    private static final String REALM2 = "/testrealm2";
    private static final String IDP1 = "https://idp1.example.com";
    private static final String IDP2 = "https://idp2.example.com";
    private static final String SP1 = "https://sp1.example.com";
    private static final String SP2 = "https://sp2.example.com";
    private static final String USER1 = "testuser1";
    private static final String USER2 = "testuser2";
    private static final String MAIL = "mail";
    private static final String PHONE_NUMBER = "phoneNumber";
    private static final String ID = "id";
    private static final String ADDRESS = "address";

    @Test
    public void requireConsentIfConsentIsEmpty() {
        AttributeConsentHistory history = new AttributeConsentHistory();

        assertTrue(history.consentRequired(REALM1, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void requireConsentIfAskAgainIsSet() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_AGAIN);

        assertTrue(history.consentRequired(REALM1, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void doNotRequireConsentIfAskIfChangeIsSetAndAlreadyAgreed() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_IF_CHANGE);

        assertFalse(history.consentRequired(REALM1, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void doNotRequireConsentIfAskIfChangeIsSetAndAttributesReduced() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_IF_CHANGE);

        assertFalse(history.consentRequired(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL))));
    }

    @Test
    public void requireConsentIfAskIfChangeIsSetButNotAgreedYet() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_IF_CHANGE);

        assertTrue(history.consentRequired(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(ID, ADDRESS))));
    }

    @Test
    public void requireConsentIfAskIfChangeIsSetButAttributesAdded() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_IF_CHANGE);

        assertTrue(history.consentRequired(REALM1, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER, ID))));
    }

    @Test
    public void doNotRequireConsentIfAskNeverIsSet() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);

        assertFalse(history.consentRequired(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(ID, ADDRESS))));
    }

    @Test
    public void doNotRequireConsentIfAskNeverIsSetInOtherSP() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);

        assertFalse(history.consentRequired(REALM1, IDP1, SP2, USER1, new HashSet<String>(Arrays.asList(MAIL,
                        PHONE_NUMBER))));
    }

    @Test
    public void cancelAskNeverIfForcedToUpdateHistory() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);

        history.update(REALM1, IDP1, SP2, USER1, new HashSet<String>(Arrays.asList(ID, ADDRESS)),
                ConsentType.ASK_IF_CHANGE);

        assertTrue(history.consentRequired(REALM1, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void historyForDifferentRealmIsIgnored() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);
        assertTrue(history.consentRequired(REALM2, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void historyForDifferentIdPIsIgnored() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);
        assertTrue(history.consentRequired(REALM1, IDP2, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void historyForDifferentUserIsIgnored() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);
        assertTrue(history.consentRequired(REALM1, IDP1, SP1, USER2,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void doNotCancelAskNeverForDifferentRealm() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);

        history.update(REALM2, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(ID, ADDRESS)),
                ConsentType.ASK_IF_CHANGE);

        assertFalse(history.consentRequired(REALM1, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void doNotCancelAskNeverForDifferentIdP() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);

        history.update(REALM1, IDP2, SP1, USER1, new HashSet<String>(Arrays.asList(ID, ADDRESS)),
                ConsentType.ASK_IF_CHANGE);

        assertFalse(history.consentRequired(REALM1, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

    @Test
    public void doNotCancelAskNeverForDifferentUser() {
        AttributeConsentHistory history = new AttributeConsentHistory();
        history.update(REALM1, IDP1, SP1, USER1, new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER)),
                ConsentType.ASK_NEVER);

        history.update(REALM1, IDP1, SP1, USER2, new HashSet<String>(Arrays.asList(ID, ADDRESS)),
                ConsentType.ASK_IF_CHANGE);

        assertFalse(history.consentRequired(REALM1, IDP1, SP1, USER1,
                new HashSet<String>(Arrays.asList(MAIL, PHONE_NUMBER))));
    }

}
