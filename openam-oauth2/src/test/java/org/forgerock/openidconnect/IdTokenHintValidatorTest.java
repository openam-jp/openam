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

package org.forgerock.openidconnect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;

import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuthProblemException;
import org.forgerock.openidconnect.IdTokenHintValidator.VerifiedIdTokenHint;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * GHSA-6f8c-crwq-jqm3: the end-session endpoint used to read the client identity and the session
 * identifier out of an {@code id_token_hint} whose signature it never checked, which let the caller
 * name any client of the realm and so pick whose registered post-logout redirect URIs applied.
 */
public class IdTokenHintValidatorTest {

    private static final String OWN_CLIENT = "the-clients-own-id";
    private static final String OWN_SECRET = "the-clients-own-secret-which-is-long-enough";
    private static final String OTHER_CLIENT = "some-other-clients-id";
    private static final String OTHER_SECRET = "some-other-clients-secret-which-is-long";
    private static final String RSA_CLIENT = "a-client-registered-for-rs256";
    private static final String ECDSA_CLIENT = "a-client-registered-for-es256";

    private static KeyPair providerRsaKeys;
    private static KeyPair providerEcdsaKeys;
    private static KeyPair someoneElsesRsaKeys;

    private OpenIdConnectClientRegistrationStore clientRegistrationStore;
    private OAuth2ProviderSettings providerSettings;
    private OAuth2Request request;
    private IdTokenHintValidator validator;

    @BeforeClass
    public static void generateKeys() throws Exception {
        providerRsaKeys = generateRsaKeyPair();
        someoneElsesRsaKeys = generateRsaKeyPair();
        providerEcdsaKeys = generateEcdsaKeyPair();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        clientRegistrationStore = mock(OpenIdConnectClientRegistrationStore.class);
        request = mock(OAuth2Request.class);

        // The provider's own signing keys, which the RSA and ECDSA id_tokens are verified with.
        providerSettings = mock(OAuth2ProviderSettings.class);
        when(providerSettings.getSigningKeyPair(JwsAlgorithm.RS256)).thenReturn(providerRsaKeys);
        when(providerSettings.getSigningKeyPair(JwsAlgorithm.ES256)).thenReturn(providerEcdsaKeys);
        OAuth2ProviderSettingsFactory providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        when(providerSettingsFactory.get(any(OAuth2Request.class))).thenReturn(providerSettings);

        validator = new IdTokenHintValidator(clientRegistrationStore, providerSettingsFactory);

        register(OWN_CLIENT, OWN_SECRET, JwsAlgorithm.HS256);
        register(OTHER_CLIENT, OTHER_SECRET, JwsAlgorithm.HS256);
        register(RSA_CLIENT, OWN_SECRET, JwsAlgorithm.RS256);
        register(ECDSA_CLIENT, OWN_SECRET, JwsAlgorithm.ES256);
    }

    private void register(String clientId, String secret, JwsAlgorithm algorithm) throws Exception {
        register(clientId, secret, algorithm.name());
    }

    private void register(String clientId, String secret, String algorithmName) throws Exception {
        OpenIdConnectClientRegistration client = mock(OpenIdConnectClientRegistration.class);
        when(client.getClientId()).thenReturn(clientId);
        when(client.getClientSecret()).thenReturn(secret);
        when(client.getIDTokenSignedResponseAlgorithm()).thenReturn(algorithmName);
        when(client.getPostLogoutRedirectUris()).thenReturn(Collections.<java.net.URI>emptySet());
        when(clientRegistrationStore.get(eq(clientId), any(OAuth2Request.class))).thenReturn(client);
    }

    /** A hint signed with the named client's secret is accepted, and identifies that client. */
    @Test
    public void acceptsAHintThisProviderSigned() throws Exception {

        VerifiedIdTokenHint hint = validator.validate(request, idTokenHint(OWN_CLIENT, OWN_SECRET));

        assertThat(hint.getClientRegistration().getClientId()).isEqualTo(OWN_CLIENT);
        assertThat(hint.getJwt().getClaimsSet().getClaim("azp", String.class)).isEqualTo(OWN_CLIENT);
    }

    /**
     * The case the advisory is about: a hint that names a client it was not issued to. Before the
     * fix the claim was taken at face value and the named client's redirect allow-list applied.
     */
    @Test
    public void rejectsAHintClaimingAClientItWasNotIssuedTo() throws Exception {

        String forged = idTokenHint(OTHER_CLIENT, OWN_SECRET);

        assertRejectedAsBadRequest(forged, "signature");
    }

    /** A hint whose signature has been replaced with something else is rejected. */
    @Test
    public void rejectsAHintWithAGarbageSignature() throws Exception {

        String signed = idTokenHint(OWN_CLIENT, OWN_SECRET);
        String tampered = signed.substring(0, signed.lastIndexOf('.') + 1) + "bm90LWEtc2lnbmF0dXJl";

        assertRejectedAsBadRequest(tampered, "signature");
    }

    /** Expiry is not enforced: logout regularly happens after the id_token has expired. */
    @Test
    public void acceptsAnExpiredHint() throws Exception {

        JwtClaimsSet claims = new JwtBuilderFactory().claims()
                .claim("azp", OWN_CLIENT)
                .claim("ops", "a-session-identifier")
                .exp(new Date(1))
                .build();

        VerifiedIdTokenHint hint = validator.validate(request, sign(claims, hmac(OWN_SECRET), JwsAlgorithm.HS256));

        assertThat(hint.getClientRegistration().getClientId()).isEqualTo(OWN_CLIENT);
    }

    /** With no client to name, there is no key to check the signature against. */
    @Test
    public void rejectsAHintThatNamesNoClient() throws Exception {

        JwtClaimsSet claims = new JwtBuilderFactory().claims().claim("ops", "a-session-identifier").build();
        String anonymous = sign(claims, hmac(OWN_SECRET), JwsAlgorithm.HS256);

        assertRejectedAsBadRequest(anonymous, "azp");
    }

    /** A hint naming a client that does not exist cannot be verified either. */
    @Test
    public void rejectsAHintNamingAnUnknownClient() throws Exception {

        // The constructors of InvalidClientException are package private, so a real one cannot be
        // built from here.
        when(clientRegistrationStore.get(eq("no-such-client"), any(OAuth2Request.class)))
                .thenThrow(mock(InvalidClientException.class));
        String hint = idTokenHint("no-such-client", OWN_SECRET);

        try {
            validator.validate(request, hint);
            failBecauseExceptionWasNotThrown(InvalidClientException.class);
        } catch (InvalidClientException expected) {
            // The client the hint names is not registered.
        }
    }

    @Test
    public void rejectsAMalformedHint() throws Exception {

        assertRejectedAsBadRequest("not-a-jwt");
    }

    @Test
    public void rejectsAMissingHint() throws Exception {

        assertRejectedAsBadRequest(null);
        assertRejectedAsBadRequest("");
    }

    /**
     * The digest is the registration's to choose, not the sender's. SignedJwt.verify() feeds the
     * header algorithm to the handler and an HMAC handler accepts whichever digest it is given, so
     * without the header being pinned this hint - correctly signed, but with HMAC-SHA512 where the
     * client is registered for HMAC-SHA256 - would verify.
     */
    @Test
    public void rejectsAHintSignedWithAnotherDigestThanTheClientIsRegisteredFor() throws Exception {

        JwtClaimsSet claims = claimsFor(OWN_CLIENT);
        String hs512 = sign(claims, hmac(OWN_SECRET), JwsAlgorithm.HS512);

        assertRejectedAsBadRequest(hs512, "signature");
    }

    /**
     * The classic forgery, and the headers that used to crash the endpoint rather than be refused
     * by it. Each one left an unchecked exception to escape into the server error path, answering
     * an unauthenticated request with server_error and a stack trace in the log.
     */
    @Test
    public void rejectsAHintWithAnUnusableHeader() throws Exception {

        assertRejectedAsBadRequest(unverifiable("{\"alg\":\"none\"}", OWN_CLIENT));
        assertRejectedAsBadRequest(unverifiable("{\"alg\":\"NONE\"}", OWN_CLIENT));
        assertRejectedAsBadRequest(unverifiable("{\"typ\":\"JWT\"}", OWN_CLIENT));
        assertRejectedAsBadRequest(unverifiable("{\"alg\":42}", OWN_CLIENT));
    }

    /** An id_token whose azp is not a string at all is a bad request, not a server error. */
    @Test
    public void rejectsAHintWhoseClientClaimIsNotAString() throws Exception {

        String hint = jwt("{\"alg\":\"HS256\"}", "{\"azp\":42}", "bm90LWEtc2lnbmF0dXJl");

        assertRejectedAsBadRequest(hint);
    }

    /** An RS256 id_token is verified against the provider's own key, not against the client's. */
    @Test
    public void acceptsAHintSignedWithTheProvidersRsaKey() throws Exception {

        String hint = sign(claimsFor(RSA_CLIENT),
                new SigningManager().newRsaSigningHandler(providerRsaKeys.getPrivate()), JwsAlgorithm.RS256);

        VerifiedIdTokenHint verified = validator.validate(request, hint);

        assertThat(verified.getClientRegistration().getClientId()).isEqualTo(RSA_CLIENT);
    }

    @Test
    public void rejectsAnRsaHintSignedWithAnotherKey() throws Exception {

        String hint = sign(claimsFor(RSA_CLIENT),
                new SigningManager().newRsaSigningHandler(someoneElsesRsaKeys.getPrivate()), JwsAlgorithm.RS256);

        assertRejectedAsBadRequest(hint, "signature");
    }

    /**
     * Algorithm confusion: the sender signs with the client secret and says HS256, hoping the
     * provider's public key is used as an HMAC key. The registration says RS256, so the header does
     * not match and it never reaches a handler.
     */
    @Test
    public void rejectsAnRsaClientsHintSignedWithTheClientSecret() throws Exception {

        String hint = sign(claimsFor(RSA_CLIENT), hmac(OWN_SECRET), JwsAlgorithm.HS256);

        assertRejectedAsBadRequest(hint, "signature");
    }

    @Test
    public void acceptsAHintSignedWithTheProvidersEcdsaKey() throws Exception {

        String hint = sign(claimsFor(ECDSA_CLIENT), new SigningManager()
                .newEcdsaSigningHandler((ECPrivateKey) providerEcdsaKeys.getPrivate()), JwsAlgorithm.ES256);

        VerifiedIdTokenHint verified = validator.validate(request, hint);

        assertThat(verified.getClientRegistration().getClientId()).isEqualTo(ECDSA_CLIENT);
    }

    /**
     * The RSA and ECDSA signing keys are read from the keystore by an alias that is the same in
     * every realm by default, so a signature alone does not say which realm a hint came from.
     */
    @Test
    public void rejectsAHintIssuedInAnotherRealm() throws Exception {

        when(request.<String>getParameter(OAuth2Constants.Params.REALM)).thenReturn("/employees");
        String hint = sign(claimsFor(RSA_CLIENT, "/customers"),
                new SigningManager().newRsaSigningHandler(providerRsaKeys.getPrivate()), JwsAlgorithm.RS256);

        assertRejectedAsBadRequest(hint, "realm");
    }

    /** The realms are compared as realm paths, not as the strings they happen to be written as. */
    @Test
    public void acceptsAHintIssuedInTheRealmOfTheRequest() throws Exception {

        when(request.<String>getParameter(OAuth2Constants.Params.REALM)).thenReturn("/employees");
        String hint = sign(claimsFor(RSA_CLIENT, "employees/"),
                new SigningManager().newRsaSigningHandler(providerRsaKeys.getPrivate()), JwsAlgorithm.RS256);

        VerifiedIdTokenHint verified = validator.validate(request, hint);

        assertThat(verified.getClientRegistration().getClientId()).isEqualTo(RSA_CLIENT);
    }

    /** A hint carrying no realm at all is a hint from the root realm, as it is everywhere else. */
    @Test
    public void acceptsARootRealmHintWithNoRealmClaim() throws Exception {

        when(request.<String>getParameter(OAuth2Constants.Params.REALM)).thenReturn("/");

        VerifiedIdTokenHint verified = validator.validate(request, idTokenHint(OWN_CLIENT, OWN_SECRET));

        assertThat(verified.getClientRegistration().getClientId()).isEqualTo(OWN_CLIENT);
    }

    /**
     * The stateless access and refresh tokens this provider mints are signed with the same key and
     * carry an aud naming their client, so a signature alone does not make a token an id_token.
     */
    @Test
    public void rejectsAProviderSignedTokenThatIsNotAnIdToken() throws Exception {

        JwtClaimsSet accessToken = claimsFor(RSA_CLIENT);
        accessToken.setClaim("tokenName", "access_token");
        String hint = sign(accessToken,
                new SigningManager().newRsaSigningHandler(providerRsaKeys.getPrivate()), JwsAlgorithm.RS256);

        assertRejectedAsBadRequest(hint, "id_token");
    }

    /** An id_token names itself, and is accepted for saying so. */
    @Test
    public void acceptsAHintThatNamesItselfAnIdToken() throws Exception {

        JwtClaimsSet claims = claimsFor(OWN_CLIENT);
        claims.setClaim("tokenName", "id_token");

        VerifiedIdTokenHint hint = validator.validate(request, sign(claims, hmac(OWN_SECRET), JwsAlgorithm.HS256));

        assertThat(hint.getClientRegistration().getClientId()).isEqualTo(OWN_CLIENT);
    }

    /**
     * A directory that cannot be read is this server's problem. Reporting it as a bad request would
     * send operators looking at the caller while the identity store is down.
     */
    @Test
    public void doesNotReportAFailingIdentityStoreAsABadRequest() throws Exception {

        when(clientRegistrationStore.get(eq(OWN_CLIENT), any(OAuth2Request.class)))
                .thenThrow(new OAuthProblemException(500, "server_error", "the directory is down", null));

        try {
            validator.validate(request, idTokenHint(OWN_CLIENT, OWN_SECRET));
            failBecauseExceptionWasNotThrown(OAuthProblemException.class);
        } catch (OAuthProblemException expected) {
            // The identity store is down, which is this server's problem.
        }
    }

    /** A client registered for 'none' has no verifiable id_tokens, and no key to go looking for. */
    @Test
    public void rejectsAHintFromAClientRegisteredForNoAlgorithm() throws Exception {

        register("an-unsigned-client", OWN_SECRET, JwsAlgorithm.NONE);

        String hint = jwt("{\"alg\":\"none\"}", "{\"azp\":\"an-unsigned-client\"}", "");

        assertRejectedAsBadRequest(hint);
        verify(providerSettings, never()).getSigningKeyPair(any(JwsAlgorithm.class));
    }

    /**
     * A hint naming its client in {@code aud} rather than in {@code azp} resolves the same way. The
     * checkSession endpoint used to read only {@code aud}, and both now read both.
     */
    @Test
    public void acceptsAHintThatNamesItsClientInAudienceOnly() throws Exception {

        JwtClaimsSet claims = new JwtBuilderFactory().claims()
                .aud(Collections.singletonList(OWN_CLIENT))
                .claim("ops", "a-session-identifier")
                .build();

        VerifiedIdTokenHint hint = validator.validate(request, sign(claims, hmac(OWN_SECRET), JwsAlgorithm.HS256));

        assertThat(hint.getClientRegistration().getClientId()).isEqualTo(OWN_CLIENT);
    }

    /** A registration naming an algorithm this provider does not know verifies nothing either. */
    @Test
    public void rejectsAHintFromAClientRegisteredForAnUnusableAlgorithm() throws Exception {

        register("a-client-registered-for-nonsense", OWN_SECRET, "PS999");
        register("a-client-registered-for-nothing", OWN_SECRET, "");

        assertRejectedAsBadRequest(idTokenHint("a-client-registered-for-nonsense", OWN_SECRET), "algorithm");
        assertRejectedAsBadRequest(idTokenHint("a-client-registered-for-nothing", OWN_SECRET), "algorithm");
    }

    /** An HMAC id_token is verified with the client's secret, so a client without one has none. */
    @Test
    public void rejectsAnHmacHintFromAClientWithNoSecret() throws Exception {

        register("a-client-with-no-secret", "", JwsAlgorithm.HS256);

        assertRejectedAsBadRequest(idTokenHint("a-client-with-no-secret", OWN_SECRET), "signature");
    }

    /** With no provider key there is nothing to check an RS256 id_token against. */
    @Test
    public void rejectsAnRsaHintWhenTheProviderHasNoSigningKey() throws Exception {

        when(providerSettings.getSigningKeyPair(JwsAlgorithm.RS256)).thenReturn(null);
        String hint = sign(claimsFor(RSA_CLIENT),
                new SigningManager().newRsaSigningHandler(providerRsaKeys.getPrivate()), JwsAlgorithm.RS256);

        assertRejectedAsBadRequest(hint, "signature");
    }

    /** An ES256 registration whose keystore alias holds an RSA key is refused, not handed the key. */
    @Test
    public void rejectsAnEcdsaHintWhenTheProviderKeyIsNotEc() throws Exception {

        when(providerSettings.getSigningKeyPair(JwsAlgorithm.ES256)).thenReturn(providerRsaKeys);
        String hint = sign(claimsFor(ECDSA_CLIENT), new SigningManager()
                .newEcdsaSigningHandler((ECPrivateKey) providerEcdsaKeys.getPrivate()), JwsAlgorithm.ES256);

        assertRejectedAsBadRequest(hint, "signature");
    }

    /**
     * An RSA handler throws on a signature that is not even the right length, where an HMAC handler
     * would answer false. The answer to an unusable token is a refusal either way, never an
     * exception escaping into the caller's error path.
     */
    @Test
    public void rejectsAnRsaHintWithATruncatedSignature() throws Exception {

        String signed = sign(claimsFor(RSA_CLIENT),
                new SigningManager().newRsaSigningHandler(providerRsaKeys.getPrivate()), JwsAlgorithm.RS256);
        String truncated = signed.substring(0, signed.lastIndexOf('.') + 1) + "AAAA";

        assertRejectedAsBadRequest(truncated, "signature");
    }

    /** A tokenName that is not a string is not a name this provider wrote. */
    @Test
    public void rejectsAHintWhoseTokenNameIsNotAString() throws Exception {

        JwtClaimsSet claims = claimsFor(OWN_CLIENT);
        claims.setClaim("tokenName", 42);

        assertRejectedAsBadRequest(sign(claims, hmac(OWN_SECRET), JwsAlgorithm.HS256), "id_token");
    }

    private void assertRejectedAsBadRequest(String idTokenHint) throws Exception {
        assertRejectedAsBadRequest(idTokenHint, null);
    }

    /**
     * Asserts that the hint is refused as a bad request, and that the refusal says why. Any other
     * exception is left to propagate, which fails the test with the exception it was answered with.
     */
    private void assertRejectedAsBadRequest(String idTokenHint, String messageContains) throws Exception {
        try {
            validator.validate(request, idTokenHint);
            failBecauseExceptionWasNotThrown(BadRequestException.class);
        } catch (BadRequestException e) {
            if (messageContains != null) {
                assertThat(e).hasMessageContaining(messageContains);
            }
        }
    }

    private String idTokenHint(String azp, String secret) {
        return sign(claimsFor(azp), hmac(secret), JwsAlgorithm.HS256);
    }

    private JwtClaimsSet claimsFor(String azp) {
        return claimsFor(azp, null);
    }

    private JwtClaimsSet claimsFor(String azp, String realm) {
        JwtClaimsSet claims = new JwtBuilderFactory().claims()
                .claim("azp", azp)
                .claim("ops", "a-session-identifier")
                .exp(new Date(System.currentTimeMillis() + 60_000))
                .build();
        if (realm != null) {
            claims.setClaim("realm", realm);
        }
        return claims;
    }

    private SigningHandler hmac(String secret) {
        return new SigningManager().newHmacSigningHandler(secret.getBytes(Utils.CHARSET));
    }

    private String sign(JwtClaimsSet claims, SigningHandler signingHandler, JwsAlgorithm algorithm) {
        return new JwtBuilderFactory()
                .jws(signingHandler)
                .headers().alg(algorithm).done()
                .claims(claims)
                .build();
    }

    /** A hint with a header of the caller's choosing, which no key can verify. */
    private String unverifiable(String header, String azp) {
        return jwt(header, "{\"azp\":\"" + azp + "\"}", "bm90LWEtc2lnbmF0dXJl");
    }

    private String jwt(String header, String claims, String signature) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(claims.getBytes(StandardCharsets.UTF_8)) + "."
                + signature;
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static KeyPair generateEcdsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
