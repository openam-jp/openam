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

package com.sun.identity.saml2.profile;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sun.identity.saml2.assertion.Assertion;
import com.sun.identity.saml2.assertion.EncryptedAssertion;
import com.sun.identity.saml2.assertion.Issuer;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.protocol.Response;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class SPACSUtilsTest {

    private static final String RESOLVING_IDP = "https://idp-a.example.com";
    private static final String OTHER_IDP = "https://idp-b.example.com";

    private final List<String> usedAssertionIDs = new ArrayList<>();

    @AfterMethod
    public void releaseAssertionIDs() {
        for (String assertionID : usedAssertionIDs) {
            SPCache.assertionByIDCache.remove(assertionID);
        }
        usedAssertionIDs.clear();
    }

    @Test
    public void markAssertionAsConsumedMarksEveryBearerAssertion() throws Exception {
        String first = newAssertionID();
        String second = newAssertionID();

        SPACSUtils.markAssertionAsConsumed(smap(first, second));

        assertThat(SPCache.assertionByIDCache.containsKey(first)).isTrue();
        assertThat(SPCache.assertionByIDCache.containsKey(second)).isTrue();
    }

    @Test
    public void markAssertionAsConsumedRejectsConsumedAssertion() throws Exception {
        String assertionID = newAssertionID();
        SPACSUtils.markAssertionAsConsumed(smap(assertionID));

        try {
            SPACSUtils.markAssertionAsConsumed(smap(assertionID));
            fail("a consumed assertion was accepted again");
        } catch (SAML2Exception expected) {
            // expected
        }
    }

    @Test
    public void markAssertionAsConsumedIsAllOrNothing() throws Exception {
        String consumed = newAssertionID();
        String fresh = newAssertionID();
        SPACSUtils.markAssertionAsConsumed(smap(consumed));

        try {
            SPACSUtils.markAssertionAsConsumed(smap(fresh, consumed));
            fail("a response carrying a consumed assertion was accepted");
        } catch (SAML2Exception expected) {
            // expected
        }

        assertThat(SPCache.assertionByIDCache.containsKey(fresh)).isFalse();
        assertThat(SPCache.assertionByIDCache.containsKey(consumed)).isTrue();
    }

    @Test(expectedExceptions = SAML2Exception.class)
    public void markAssertionAsConsumedRejectsMapWithoutBearerAssertion() throws Exception {
        SPACSUtils.markAssertionAsConsumed(new HashMap());
    }

    @Test(expectedExceptions = SAML2Exception.class)
    public void markAssertionAsConsumedRejectsEmptyBearerAssertions() throws Exception {
        Map smap = new HashMap();
        smap.put(SAML2Constants.BEARER_ASSERTION_IDS, new LinkedHashMap<String, Long>());
        SPACSUtils.markAssertionAsConsumed(smap);
    }

    private String newAssertionID() {
        String assertionID = "_" + UUID.randomUUID().toString();
        usedAssertionIDs.add(assertionID);
        return assertionID;
    }

    private static Map smap(String... assertionIDs) {
        Map<String, Long> bearerAssertionIDs = new LinkedHashMap<>();
        for (String assertionID : assertionIDs) {
            bearerAssertionIDs.put(assertionID, System.currentTimeMillis() + 60000L);
        }
        Map smap = new HashMap();
        smap.put(SAML2Constants.BEARER_ASSERTION_IDS, bearerAssertionIDs);
        return smap;
    }

    @Test
    public void artifactResponseIssuedByResolvingIdpIsBound() {
        Response res = response(issuer(RESOLVING_IDP), Arrays.asList(assertion(issuer(RESOLVING_IDP))), null);

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isTrue();
    }

    @Test
    public void artifactResponseIssuedByOtherIdpIsUnbound() {
        Response res = response(issuer(OTHER_IDP), Arrays.asList(assertion(issuer(OTHER_IDP))), null);

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isFalse();
    }

    @Test
    public void artifactResponseWithIssuerWithoutValueIsUnbound() {
        Response res = response(issuer(null), Arrays.asList(assertion(issuer(RESOLVING_IDP))), null);

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isFalse();
    }

    @Test
    public void artifactResponseWithoutIssuerIsBoundByItsAssertions() {
        Response res = response(null,
                Arrays.asList(assertion(issuer(RESOLVING_IDP)), assertion(issuer(RESOLVING_IDP))), null);

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isTrue();
    }

    @Test
    public void artifactResponseWithoutIssuerAndAssertionOfOtherIdpIsUnbound() {
        Response res = response(null,
                Arrays.asList(assertion(issuer(RESOLVING_IDP)), assertion(issuer(OTHER_IDP))), null);

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isFalse();
    }

    @Test
    public void artifactResponseWithoutIssuerAndAssertionWithoutIssuerIsUnbound() {
        Response res = response(null, Arrays.asList(assertion(null)), null);

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isFalse();
    }

    @Test
    public void artifactResponseWithoutIssuerAndEncryptedAssertionIsUnbound() {
        Response res = response(null, null, Arrays.asList(mock(EncryptedAssertion.class)));

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isFalse();
    }

    @Test
    public void artifactResponseWithIssuerAndEncryptedAssertionIsBound() {
        Response res = response(issuer(RESOLVING_IDP), null, Arrays.asList(mock(EncryptedAssertion.class)));

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isTrue();
    }

    @Test
    public void artifactResponseWithoutIssuerAndEmptyListsIsBound() {
        // verifyResponse rejects a Response without any assertion.
        Response res = response(null, Collections.emptyList(), Collections.emptyList());

        assertThat(SPACSUtils.isArtifactResponseBoundTo(RESOLVING_IDP, res)).isTrue();
    }

    private static Response response(Issuer issuer, List assertions, List encryptedAssertions) {
        Response res = mock(Response.class);
        when(res.getIssuer()).thenReturn(issuer);
        when(res.getAssertion()).thenReturn(assertions);
        when(res.getEncryptedAssertion()).thenReturn(encryptedAssertions);
        return res;
    }

    private static Assertion assertion(Issuer issuer) {
        Assertion assertion = mock(Assertion.class);
        when(assertion.getIssuer()).thenReturn(issuer);
        return assertion;
    }

    private static Issuer issuer(String value) {
        Issuer issuer = mock(Issuer.class);
        when(issuer.getValue()).thenReturn(value);
        return issuer;
    }
}
