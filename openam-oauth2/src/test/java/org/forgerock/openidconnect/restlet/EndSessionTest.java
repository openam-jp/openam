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
 * Copyright 2026 3A Systems, LLC.
 * Portions copyright 2026 OSSTech Corporation
 */

package org.forgerock.openidconnect.restlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import java.util.Date;

import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.restlet.ExceptionHandler;
import org.forgerock.oauth2.restlet.OAuth2RestletException;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openidconnect.IdTokenHintValidator;
import org.forgerock.openidconnect.OpenIDConnectEndSession;
import org.forgerock.openidconnect.OpenIdConnectClientRegistration;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;
import org.mockito.ArgumentCaptor;
import org.restlet.Context;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.Method;
import org.restlet.data.Status;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * GHSA-6f8c-crwq-jqm3: the end-session endpoint decided which client's registered post-logout
 * redirect URIs applied from the {@code azp} claim of an {@code id_token_hint} it never verified,
 * so the caller chose whose allow-list it was measured against.
 */
public class EndSessionTest {

    private static final String OWN_CLIENT = "the-clients-own-id";
    private static final String OWN_SECRET = "the-clients-own-secret-which-is-long-enough";
    private static final URI OWN_LOGOUT_URI = URI.create("https://rp.example.com/logged-out");

    private static final String OTHER_CLIENT = "some-other-clients-id";
    private static final String OTHER_SECRET = "some-other-clients-secret-which-is-long";
    private static final URI OTHER_LOGOUT_URI = URI.create("https://attacker.example.com/logged-out");

    // The RSA id_tokens of every client in a realm are signed with one provider key pair, so for
    // these two clients a signature says nothing about which of them a hint belongs to.
    private static final String OWN_RSA_CLIENT = "the-clients-own-id-registered-for-rs256";

    private static KeyPair providerRsaKeys;

    private OpenIdConnectClientRegistrationStore clientRegistrationStore;
    private OpenIDConnectEndSession openIDConnectEndSession;
    private OAuth2ProviderSettings providerSettings;
    private OAuth2Request oAuth2Request;
    private Response response;
    private EndSession endSession;

    @BeforeClass
    public static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        providerRsaKeys = generator.generateKeyPair();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        clientRegistrationStore = mock(OpenIdConnectClientRegistrationStore.class);
        register(OWN_CLIENT, OWN_SECRET, JwsAlgorithm.HS256, OWN_LOGOUT_URI);
        register(OTHER_CLIENT, OTHER_SECRET, JwsAlgorithm.HS256, OTHER_LOGOUT_URI);
        register(OWN_RSA_CLIENT, OWN_SECRET, JwsAlgorithm.RS256, OWN_LOGOUT_URI);

        openIDConnectEndSession = mock(OpenIDConnectEndSession.class);

        oAuth2Request = mock(OAuth2Request.class);
        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        given(requestFactory.create(any(Request.class))).willReturn(oAuth2Request);

        // Stubbed rather than bare, so that a client registered for anything but HMAC resolves a key
        // instead of failing on a null provider settings and passing these tests for that reason.
        providerSettings = mock(OAuth2ProviderSettings.class);
        given(providerSettings.getSigningKeyPair(JwsAlgorithm.RS256)).willReturn(providerRsaKeys);
        given(providerSettings.isOidcRpInitiatedLogoutEnabled()).willReturn(true);
        OAuth2ProviderSettingsFactory providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        given(providerSettingsFactory.get(any(OAuth2Request.class))).willReturn(providerSettings);

        IdTokenHintValidator idTokenHintValidator = new IdTokenHintValidator(clientRegistrationStore,
                providerSettingsFactory);

        endSession = spy(new EndSession(requestFactory, openIDConnectEndSession, mock(ExceptionHandler.class),
                idTokenHintValidator, providerSettingsFactory));

        Request request = new Request(Method.GET, "https://openam.example.com/oauth2/connect/endSession");
        response = new Response(request);
        given(endSession.getRequest()).willReturn(request);
        given(endSession.getResponse()).willReturn(response);
        given(endSession.getContext()).willReturn(new Context());
    }

    private void register(String clientId, String secret, JwsAlgorithm algorithm, URI postLogoutRedirectUri)
            throws Exception {
        OpenIdConnectClientRegistration client = mock(OpenIdConnectClientRegistration.class);
        when(client.getClientId()).thenReturn(clientId);
        when(client.getClientSecret()).thenReturn(secret);
        when(client.getIDTokenSignedResponseAlgorithm()).thenReturn(algorithm.name());
        when(client.getPostLogoutRedirectUris()).thenReturn(Collections.singleton(postLogoutRedirectUri));
        when(clientRegistrationStore.get(eq(clientId), any(OAuth2Request.class))).thenReturn(client);
    }

    /**
     * The advisory: a hint issued to one client, presented with another client's registered
     * post-logout redirect URI. The hint is genuine - it is the {@code azp} claim that used to be
     * taken at face value - so before the fix the other client's allow-list applied and the
     * redirect was performed.
     */
    @Test
    public void refusesToRedirectToAnotherClientsRegisteredUri() throws Exception {

        endSessionRequest(idTokenHint(OWN_CLIENT, OWN_SECRET), OTHER_LOGOUT_URI.toString());

        assertEndSessionRefused();
        assertThat(response.getStatus()).isNotEqualTo(Status.REDIRECTION_FOUND);
        // The hint itself is genuine, so the session it names is ended; it is only the redirect that
        // is refused, and it is refused after the session has gone. Pinned rather than left implicit
        // because the order is a deliberate choice: validating first would leave a user who asked to
        // log out logged in.
        assertForwarded(OWN_CLIENT, OWN_SECRET);
    }

    /** A hint naming a client it was not issued to never reaches the redirect decision at all. */
    @Test
    public void refusesAHintForgedToNameAnotherClient() throws Exception {

        // Signed with one client's secret, but claiming to have been issued to the other.
        endSessionRequest(idTokenHint(OTHER_CLIENT, OWN_SECRET), OTHER_LOGOUT_URI.toString());

        assertEndSessionRefused();
        assertThat(response.getStatus()).isNotEqualTo(Status.REDIRECTION_FOUND);
        verify(openIDConnectEndSession, never()).endSession(any(OAuth2Request.class), any(SignedJwt.class));
    }

    /** A hint resolving to its own registration is redirected to that client's own URI. */
    @Test
    public void redirectsAnRsaClientToItsOwnRegisteredUri() throws Exception {

        endSessionRequest(rsaIdTokenHint(OWN_RSA_CLIENT), OWN_LOGOUT_URI.toString());

        endSession.endSession();

        assertThat(response.getStatus()).isEqualTo(Status.REDIRECTION_FOUND);
    }

    /** A client's own registered URI is still redirected to. */
    @Test
    public void redirectsToTheHintsOwnClientsRegisteredUri() throws Exception {

        endSessionRequest(idTokenHint(OWN_CLIENT, OWN_SECRET), OWN_LOGOUT_URI.toString());

        endSession.endSession();

        assertThat(response.getStatus()).isEqualTo(Status.REDIRECTION_FOUND);
        assertThat(response.getLocationRef().toString()).isEqualTo(OWN_LOGOUT_URI.toString());
        assertForwarded(OWN_CLIENT, OWN_SECRET);
    }

    /** A logout with no redirect still ends the session named by the verified hint. */
    @Test
    public void endsTheSessionWithNoRedirectRequested() throws Exception {

        endSessionRequest(idTokenHint(OWN_CLIENT, OWN_SECRET), null);

        assertThat(endSession.endSession()).isNull();

        assertForwarded(OWN_CLIENT, OWN_SECRET);
    }

    /**
     * RP-Initiated Logout is off by default in this distribution. The endpoint refuses before the
     * hint is verified, so a caller cannot drive signature checking against a disabled endpoint.
     */
    @Test
    public void refusesEverythingWhenRpInitiatedLogoutIsDisabled() throws Exception {

        given(providerSettings.isOidcRpInitiatedLogoutEnabled()).willReturn(false);
        endSessionRequest(idTokenHint(OWN_CLIENT, OWN_SECRET), OWN_LOGOUT_URI.toString());

        assertEndSessionRefused();
        assertThat(response.getStatus()).isNotEqualTo(Status.REDIRECTION_FOUND);
        verify(openIDConnectEndSession, never()).endSession(any(OAuth2Request.class), any(SignedJwt.class));
        verify(providerSettings, never()).getSigningKeyPair(any(JwsAlgorithm.class));
    }

    /**
     * A post_logout_redirect_uri that is not a URI at all matches nothing the client registered.
     * It used to reach {@code URI.create} and throw past the OAuth2Exception handler - a server
     * error on an unauthenticated endpoint, raised after the session had already been ended.
     */
    @Test
    public void refusesAPostLogoutRedirectUriThatIsNotAUri() throws Exception {

        endSessionRequest(idTokenHint(OWN_CLIENT, OWN_SECRET), "http://[");

        assertEndSessionRefused();
        assertThat(response.getStatus()).isNotEqualTo(Status.REDIRECTION_FOUND);
    }

    @Test
    public void refusesARequestWithNoHint() throws Exception {

        endSessionRequest(null, OWN_LOGOUT_URI.toString());

        assertEndSessionRefused();
        verify(openIDConnectEndSession, never()).endSession(any(OAuth2Request.class), any(SignedJwt.class));
    }

    /** Asserts that the endpoint refused the request, as the exception its handler renders. */
    private void assertEndSessionRefused() throws Exception {

        try {
            endSession.endSession();
            failBecauseExceptionWasNotThrown(OAuth2RestletException.class);
        } catch (OAuth2RestletException expected) {
            // The endpoint refused the request.
        }
    }

    /**
     * Pins that the token handed on is the hint that was verified, and not merely some SignedJwt.
     * {@code any(SignedJwt.class)} would be satisfied by a different, unverified token, which is the
     * one property the {@code String} to {@code SignedJwt} change exists to guarantee.
     */
    private void assertForwarded(String clientId, String secret) throws Exception {

        ArgumentCaptor<SignedJwt> forwarded = ArgumentCaptor.forClass(SignedJwt.class);
        verify(openIDConnectEndSession).endSession(any(OAuth2Request.class), forwarded.capture());

        SignedJwt jwt = forwarded.getValue();
        assertThat(jwt.getClaimsSet().getClaim("azp", String.class)).isEqualTo(clientId);
        assertThat(jwt.getClaimsSet().getClaim("ops", String.class)).isEqualTo(sessionOf(clientId));
        assertThat(jwt.verify(new SigningManager().newHmacSigningHandler(secret.getBytes(Utils.CHARSET))))
                .isTrue();
    }

    private void endSessionRequest(String idTokenHint, String postLogoutRedirectUri) {
        given(oAuth2Request.<String>getParameter(OAuth2Constants.Params.END_SESSION_ID_TOKEN_HINT))
                .willReturn(idTokenHint);
        given(oAuth2Request.<String>getParameter(OAuth2Constants.Params.POST_LOGOUT_REDIRECT_URI))
                .willReturn(postLogoutRedirectUri);
    }

    private String idTokenHint(String azp, String secret) {
        return new JwtBuilderFactory()
                .jws(new SigningManager().newHmacSigningHandler(secret.getBytes(Utils.CHARSET)))
                .headers().alg(JwsAlgorithm.HS256).done()
                .claims(claimsFor(azp))
                .build();
    }

    /** A hint signed with the provider's own key, as an RS256 client's id_tokens are. */
    private String rsaIdTokenHint(String azp) {
        return new JwtBuilderFactory()
                .jws(new SigningManager().newRsaSigningHandler(providerRsaKeys.getPrivate()))
                .headers().alg(JwsAlgorithm.RS256).done()
                .claims(claimsFor(azp))
                .build();
    }

    private JwtClaimsSet claimsFor(String azp) {
        return new JwtBuilderFactory().claims()
                .claim("azp", azp)
                // Distinct per client, so that asserting on it says which client's session was ended.
                .claim("ops", sessionOf(azp))
                .exp(new Date(System.currentTimeMillis() + 60_000))
                .build();
    }

    private static String sessionOf(String clientId) {
        return "the-session-of-" + clientId;
    }
}
