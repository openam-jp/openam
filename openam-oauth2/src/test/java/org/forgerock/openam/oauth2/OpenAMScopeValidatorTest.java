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
 * Copyright 2014-2015 ForgeRock AS.
 *
 * Portions Copyrighted 2019 OGIS-RI Co., Ltd.
 */

package org.forgerock.openam.oauth2;

import static org.assertj.core.api.Assertions.*;
import static org.forgerock.openam.utils.CollectionUtils.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.sun.identity.idm.AMIdentity;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.openam.scripting.ScriptEvaluator;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class OpenAMScopeValidatorTest {

    private OpenAMScopeValidator validator;
    private OAuth2Request request;
    private OAuth2ProviderSettings providerSettings;
    private ClientRegistration client;
    private OpenIdConnectClientRegistrationStore clientRegistrationStore;
    private AMIdentity identity;

    @BeforeMethod
    public void setup() throws Exception {
        client = mock(ClientRegistration.class);
        request = mock(OAuth2Request.class);
        providerSettings = mock(OAuth2ProviderSettings.class);
        clientRegistrationStore = mock(OpenIdConnectClientRegistrationStore.class);
        OAuth2ProviderSettingsFactory factory = mock(OAuth2ProviderSettingsFactory.class);
        when(factory.get(request)).thenReturn(providerSettings);
        ScriptEvaluator scriptEvaluator = mock(ScriptEvaluator.class);
        IdentityManager identityManager = mock(IdentityManager.class);
        identity = mock(AMIdentity.class);
        when(identityManager.getResourceOwnerIdentity(nullable(String.class), nullable(String.class))).thenReturn(identity);
        validator = new OpenAMScopeValidator(identityManager, null, factory, null, scriptEvaluator,
                clientRegistrationStore, null);
    }

    @Test
    public void shouldReturnValidAuthorizationScopes() throws Exception {
        // Given
        when(client.getAllowedScopes()).thenReturn(asSet("a", "b", "c"));

        // When
        Set<String> scopes = validator.validateAuthorizationScope(client, asSet("a", "b"), request);

        // Then
        assertThat(scopes).containsOnly("a", "b");
    }

    @Test
    public void shouldReturnValidAccessTokenScopes() throws Exception {
        // Given
        when(client.getAllowedScopes()).thenReturn(asSet("a", "b", "c"));

        // When
        Set<String> scopes = validator.validateAccessTokenScope(client, asSet("a", "b"), request);

        // Then
        assertThat(scopes).containsOnly("a", "b");
    }

    @Test
    public void shouldReturnValidRefreshTokenScopes() throws Exception {
        // Given
        when(client.getAllowedScopes()).thenReturn(asSet("x", "y", "z"));

        // When
        Set<String> scopes = validator.validateRefreshTokenScope(client, asSet("a", "b"), asSet("a", "b", "c"), request);

        // Then
        assertThat(scopes).containsOnly("a", "b");
    }

    @Test
    public void shouldReturnDefaultScopesWhenNoneRequested() throws Exception {
        // Given
        when(client.getDefaultScopes()).thenReturn(asSet("a", "b"));

        // When
        Set<String> scopes = validator.validateAuthorizationScope(client, new HashSet<String>(), request);

        // Then
        assertThat(scopes).containsOnly("a", "b");
    }

    @Test(expectedExceptions = InvalidScopeException.class)
    public void shouldThrowExceptionForUnknownScopes() throws Exception {
        // Given
        when(client.getAllowedScopes()).thenReturn(asSet("a", "b", "c"));

        // When
        validator.validateAuthorizationScope(client, asSet("a", "b", "d"), request);
    }

    @Test(expectedExceptions = InvalidScopeException.class)
    public void shouldThrowExceptionForNoScopes() throws Exception {
        // Given
        when(client.getAllowedScopes()).thenReturn(asSet("a", "b", "c"));

        // When
        validator.validateAuthorizationScope(client, Collections.<String>emptySet(), request);
    }

    @Test
    public void shouldReturnEmptyScopeMap() throws Exception {
        // given
        AccessToken accessToken = mock(AccessToken.class);
        when(accessToken.getScope()).thenReturn(Collections.<String>emptySet());

        // when
        Map<String, Object> result = validator.evaluateScope(accessToken);

        // then
        assertThat(result).isEmpty();
    }

    @Test
    public void shouldReturnScopesWithValues() throws Exception {
        // given
        String scopeKey1 = "mail";
        String scopeKey2 = "phone";
        String scopeValue1 = "test@example.com";
        String scopeValue2 = "1234567890";
        AccessToken accessToken = mock(AccessToken.class);
        when(accessToken.getScope()).thenReturn(new HashSet<>(Arrays.asList(scopeKey1, scopeKey2)));
        when(accessToken.getResourceOwnerId()).thenReturn("owner");
        when(identity.getAttribute(scopeKey1)).thenReturn(Collections.singleton(scopeValue1));
        when(identity.getAttribute(scopeKey2)).thenReturn(Collections.singleton(scopeValue2));

        // when
        Map<String, Object> result = validator.evaluateScope(accessToken);

        // then
        assertThat(result).isNotNull();
        assertThat(result).isNotEmpty();
        assertThat(result.get(scopeKey1)).isEqualTo(scopeValue1);
        assertThat(result.get(scopeKey2)).isEqualTo(scopeValue2);
    }

    @Test
    public void shouldReturnScopesWithoutValues() throws Exception {
        // given
        String scopeKey1 = "mail";
        String scopeKey2 = "phone";
        AccessToken accessToken = mock(AccessToken.class);
        when(accessToken.getScope()).thenReturn(new HashSet<>(Arrays.asList(scopeKey1, scopeKey2)));
        when(accessToken.getResourceOwnerId()).thenReturn("owner");
        when(identity.getAttribute(scopeKey1)).thenReturn(Collections.emptySet());
        when(identity.getAttribute(scopeKey2)).thenReturn(null);

        // when
        Map<String, Object> result = validator.evaluateScope(accessToken);

        // then
        assertThat(result).isNotNull();
        assertThat(result).isNotEmpty();
        assertThat(result.get(scopeKey1)).isEqualTo("");
        assertThat(result.get(scopeKey2)).isEqualTo("");
    }
}
