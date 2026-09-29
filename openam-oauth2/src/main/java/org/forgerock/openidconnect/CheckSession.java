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
 * Copyright 2013-2015 ForgeRock AS.
 * Portions copyright 2026 OSSTech Corporation
 * Portions copyright 2026 3A Systems, LLC.
 */

package org.forgerock.openidconnect;

import static org.forgerock.openam.oauth2.OAuth2Constants.JWTTokenParams.*;
import static org.forgerock.openam.utils.CollectionUtils.getFirstItem;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsAlgorithmType;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.cts.CTSPersistentStore;
import org.forgerock.openam.cts.adapters.TokenAdapter;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.utils.OpenAMSettings;

/**
 * Interface is to define what needs to be implemented to do the OpenID Connect check session endpoint.
 *
 * @since 12.0.0
 * @supported.all.api
 */
public class CheckSession {

    private final Debug logger = Debug.getInstance("OAuth2Provider");
    private final SSOTokenManager ssoTokenManager;
    private final OpenAMSettings openAMSettings;
    private final OpenIdConnectClientRegistrationStore clientRegistrationStore;
    private final CTSPersistentStore cts;
    private final TokenAdapter<JsonValue> tokenAdapter;
    private final IdTokenSignatureVerifier signatureVerifier;
    private final OAuth2ProviderSettingsFactory providerSettingsFactory;

    /**
     * Constructs a new CheckSession.
     */
    public CheckSession() {
        this(InjectorHolder.getInstance(SSOTokenManager.class),
                InjectorHolder.getInstance(OpenAMSettings.class),
                InjectorHolder.getInstance(OpenIdConnectClientRegistrationStore.class),
                InjectorHolder.getInstance(CTSPersistentStore.class),
                InjectorHolder.getInstance(Key.get(new TypeLiteral<TokenAdapter<JsonValue>>() { },
                        Names.named(OAuth2Constants.CoreTokenParams.OAUTH_TOKEN_ADAPTER))),
                new IdTokenSignatureVerifier(InjectorHolder.getInstance(SigningManager.class)),
                InjectorHolder.getInstance(OAuth2ProviderSettingsFactory.class));
    }

    CheckSession(SSOTokenManager ssoTokenManager, OpenAMSettings openAMSettings,
            OpenIdConnectClientRegistrationStore clientRegistrationStore, CTSPersistentStore cts,
            TokenAdapter<JsonValue> tokenAdapter, IdTokenSignatureVerifier signatureVerifier,
            OAuth2ProviderSettingsFactory providerSettingsFactory) {
        this.ssoTokenManager = ssoTokenManager;
        this.openAMSettings = openAMSettings;
        this.clientRegistrationStore = clientRegistrationStore;
        this.cts = cts;
        this.tokenAdapter = tokenAdapter;
        this.signatureVerifier = signatureVerifier;
        this.providerSettingsFactory = providerSettingsFactory;
    }

    /**
     * Whether OpenID Connect Session Management is enabled for the realm of the request. As the
     * checkSession endpoint is not realm specific, the realm is taken from the id_token of the
     * request, and the feature is treated as disabled when the realm cannot be determined.
     *
     * <p>The realm claim is read before the signature is checked, which is safe: it only selects
     * whose setting is read. Naming a realm that has the feature switched on gains the caller
     * nothing, because {@link #getClientSessionURI} and {@link #getValidSession} resolve the client
     * registration and the provider signing key from that same claim and then verify the signature,
     * so a token issued somewhere else is refused there. The switch is read first so that a realm
     * which has turned this endpoint off does no signature checking on a caller's behalf.
     *
     * @param request The HttpServletRequest.
     * @return {@code true} if OpenID Connect Session Management is enabled.
     */
    public boolean isSessionManagementEnabled(HttpServletRequest request) {

        final SignedJwt jwt = getIDToken(request);

        if (jwt == null) {
            return false;
        }

        final String realm;
        try {
            realm = realmOf(jwt);
        } catch (RuntimeException e) {
            // A realm claim that is not a string at all. Every byte of the token is caller-written,
            // so this has to read as a refusal rather than as an exception out of the JSP that
            // serves this iframe, which has no try of its own.
            logger.warning("The realm claim of the id_token supplied to the checkSession endpoint cannot be read: "
                    + e.getClass().getSimpleName());
            logger.message("The realm claim of the id_token supplied to the checkSession endpoint cannot be read", e);
            return false;
        }

        if (realm == null) {
            logger.warning("No realm found in the id_token supplied to the checkSession endpoint");
            return false;
        }

        try {
            return providerSettingsFactory.get(OAuth2Request.forRealm(realm)).isOidcSessionManagementEnabled();
        } catch (NotFoundException e) {
            // The realm is named by the caller's own token, so one that does not exist is a refusal
            // rather than a fault of this server.
            logger.warning("The id_token supplied to the checkSession endpoint names realm '"
                    + IdTokenSignatureVerifier.forLog(realm) + "', which has no OAuth2 provider");
            logger.message("The id_token supplied to the checkSession endpoint names a realm with no provider", e);
            return false;
        } catch (ServerException e) {
            logger.error("Unable to read the OAuth2 provider settings of the realm the id_token names", e);
            return false;
        }
    }

    /**
     * Get the cookie name containing the session information.
     *
     * @return The cookie name.
     */
    public String getCookieName() {
        return openAMSettings.getSSOCookieName();
    }

    /**
     * Get the URL the postMessage must be coming from (registered in client) to process the message.
     *
     * @param request The HttpServletRequest.
     * @return The url as a string or empty String.
     */
    public String getClientSessionURI(HttpServletRequest request) {

        SignedJwt jwt = getIDToken(request);

        if (jwt == null) {
            return "";
        }

        try {
            final OpenIdConnectClientRegistration clientRegistration = getClientRegistration(jwt);

            // A token naming no client names no key either, so there is nothing to check its
            // signature against and no registration to answer from.
            if (clientRegistration == null || !isJwtValid(jwt, clientRegistration)) {
                return "";
            }

            return clientRegistration.getClientSessionURI();
        } catch (Exception e) {
            // The id_token was read out of the Referer, so its claims - the client it names among
            // them - are whatever the caller wrote. The registration's own accessors throw
            // unchecked on a datastore fault, and getClientSessionURI() and
            // getIDTokenSignedResponseAlgorithm() are both reached from inside here, so the catch
            // has to span them: an answer of "", never an exception out of the JSP that serves this
            // iframe. getValidSession() answers false to the same failure.
            // The stack goes to a debug level: this endpoint is polled by every RP iframe, and the
            // Referer that drives the failure is the caller's.
            logger.warning("Unable to read the client session URI out of the id_token: "
                    + e.getClass().getSimpleName());
            logger.message("Unable to read the client session URI out of the id_token", e);
            return "";
        }
    }

    /**
     * Gets the Client's registration based from the client named by the JWT.
     *
     * @param jwt The JWT.
     * @return The Client's registration, or {@code null} if the JWT names no client.
     * @throws InvalidClientException If the client's registration is not found.
     */
    private OpenIdConnectClientRegistration getClientRegistration(SignedJwt jwt)
            throws InvalidClientException, NotFoundException {

        // Resolved the same way as on the endSession path, so that the two endpoints cannot
        // disagree about which client an id_token belongs to.
        final String client = IdTokenSignatureVerifier.clientIdOf(jwt);
        if (client == null) {
            return null;
        }
        return clientRegistrationStore.get(client, OAuth2Request.forRealm(realmOf(jwt)));
    }

    private String realmOf(Jwt jwt) {
        return jwt.getClaimsSet().get(REALM).asString();
    }

    /**
     * Determines if the specified signed JWT carries a signature this provider produced.
     *
     * <p>The algorithm comes from the client's registration and is pinned against the token header,
     * and an id_token signed with one of the provider's own key pairs is verified with that key
     * rather than with the client's secret.
     *
     * <p>This used to answer the opposite of its name - {@code true} for a token that did not
     * verify - and both callers negated it, so a valid id_token was refused and an invalid one was
     * answered as though it were genuine.
     *
     * @param jwt The signed JWT.
     * @param clientRegistration The client's registration.
     * @return {@code true} if the JWT is valid.
     */
    private boolean isJwtValid(SignedJwt jwt, OpenIdConnectClientRegistration clientRegistration) {

        // A stateless access or refresh token is signed with the same provider key an RS256
        // id_token is, and carries an aud naming its client, so the signature alone does not say
        // what kind of token this is. The endSession path refuses one; so does this.
        if (!IdTokenSignatureVerifier.isIdToken(jwt)) {
            logger.warning("The token supplied to the checkSession endpoint is not an id_token");
            return false;
        }

        final JwsAlgorithm algorithm = IdTokenSignatureVerifier.registeredAlgorithm(
                clientRegistration.getIDTokenSignedResponseAlgorithm());
        if (algorithm == null) {
            logger.warning("Client '" + clientRegistration.getClientId()
                    + "' has no usable id_token signing algorithm");
            return false;
        }

        PublicKey signingKey = null;
        if (!JwsAlgorithmType.HMAC.equals(algorithm.getAlgorithmType())) {
            try {
                final KeyPair signingKeyPair = openAMSettings.getSigningKeyPair(realmOf(jwt), algorithm);
                signingKey = signingKeyPair == null ? null : signingKeyPair.getPublic();
            } catch (Exception e) {
                logger.error("Unable to read the signing key the id_token has to be verified with", e);
                return false;
            }
        }

        return signatureVerifier.isSignatureValid(jwt, algorithm, clientRegistration.getClientSecret(), signingKey);
    }

    /**
     * Check if the JWT contains a valid session id.
     *
     * @param request The HttpServletRequset.
     * @return {@code true} if valid.
     */
    public boolean getValidSession(HttpServletRequest request) {
        SignedJwt jwt = getIDToken(request);

        if (jwt == null) {
            return false;
        }

        try {
            final OpenIdConnectClientRegistration clientRegistration = getClientRegistration(jwt);

            // A token naming no client names no key either, so there is nothing to check its
            // signature against.
            if (clientRegistration == null || !isJwtValid(jwt, clientRegistration)) {
                return false;
            }

            String opsId = (String) jwt.getClaimsSet().getClaim(OPS);
            if (opsId == null) {
                opsId = (String) jwt.getClaimsSet().getClaim(LEGACY_OPS);
            }
            JsonValue idTokenUserSessionToken = tokenAdapter.fromToken(cts.read(opsId));
            // CTS attributes are multi-valued and StatefulTokenStore writes field(LEGACY_OPS, set(ops)),
            // so asString() threw for every genuine token and this endpoint answered "changed" whatever
            // the signature said. OpenIDConnectProvider reads it this way.
            String sessionId = getFirstItem(idTokenUserSessionToken.get(LEGACY_OPS).asSet(String.class));

            SSOToken ssoToken = ssoTokenManager.createSSOToken(sessionId);
            return ssoTokenManager.isValidToken(ssoToken);
        } catch (Exception e){
            // Driven by the caller's own Referer - an id_token naming a client that does not exist
            // reaches this too - so the stack goes to a debug level rather than being written out
            // for every poll of an RP iframe.
            logger.warning("Unable to get the SSO token: " + e.getClass().getSimpleName());
            logger.message("Unable to get the SSO token", e);
            return false;
        }
    }

    private SignedJwt getIDToken(HttpServletRequest request) {
        URI referer = null;
        try {
            referer = new URI(request.getHeader("Referer"));
        } catch (Exception e){
            // A request with no Referer header at all lands here, which is every request that is
            // not the RP iframe, so this cannot be written out at an error level with a stack.
            logger.warning("No id_token supplied to the checkSession endpoint: " + e.getClass().getSimpleName());
            logger.message("No id_token supplied to the checkSession endpoint", e);
            return null;
        }
        Map<String, String> map = null;
        if (referer != null && referer.getQuery() != null && !referer.getQuery().isEmpty()){
            String query =  referer.getQuery();
            String[] params = query.split("&");
            map = new HashMap<String, String>();
            for (String param : params){
                int split = param.indexOf('=');
                if (split < 0) {
                    // A valueless query segment, which the Referer is free to carry. substring(0, -1)
                    // threw out of here, and getIDToken is called outside its callers' try blocks.
                    continue;
                }
                String name = param.substring(0, split);
                String value = param.substring(split+1, param.length());
                map.put(name, value);
            }
        }

        if (map != null && map.containsKey(ID_TOKEN)){
            String id_token = map.get(ID_TOKEN);

            try {
                JwtReconstruction jwtReconstruction = new JwtReconstruction();
                return jwtReconstruction.reconstructJwt(id_token, SignedJwt.class);
            } catch (RuntimeException e) {
                logger.warning("The id_token supplied to the checkSession endpoint could not be parsed: "
                        + e.getClass().getSimpleName());
                logger.message("The id_token supplied to the checkSession endpoint could not be parsed", e);
                return null;
            }
        }
        return null;
    }
}
