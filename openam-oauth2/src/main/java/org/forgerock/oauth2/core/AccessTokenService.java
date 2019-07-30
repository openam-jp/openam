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
 * Portions copyright 2019 Open Source Solution Technology Corporation
 */

package org.forgerock.oauth2.core;

import static org.forgerock.oauth2.core.Utils.isEmpty;
import static org.forgerock.oauth2.core.Utils.joinScope;
import static org.forgerock.oauth2.core.Utils.splitScope;
import static org.forgerock.openam.audit.AuditConstants.TrackingIdKey.OAUTH2_GRANT;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.GRANT_TYPE;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.REFRESH_TOKEN;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.SCOPE;

import javax.inject.Inject;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.forgerock.oauth2.core.exceptions.AuthorizationDeclinedException;
import org.forgerock.oauth2.core.exceptions.AuthorizationPendingException;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.ExpiredTokenException;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidCodeException;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.openam.oauth2.IdentityManager;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.identity.idm.AMIdentity;

/**
 * Handles access token requests from OAuth2 clients to the OAuth2 provider to grant access tokens for the requested
 * grant types.
 *
 * @since 12.0.0
 */
public class AccessTokenService {

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");
    private final Map<String, ? extends GrantTypeHandler> grantTypeHandlers;
    private final ClientAuthenticator clientAuthenticator;
    private final TokenStore tokenStore;
    private final OAuth2ProviderSettingsFactory providerSettingsFactory;
    private final OAuth2UrisFactory urisFactory;
    private final IdentityManager identityManager;

    /**
     * Constructs a new AccessTokenServiceImpl.
     * @param grantTypeHandlers A {@code Map} of the grant type handlers.
     * @param clientAuthenticator An instance of the ClientAuthenticator.
     * @param tokenStore An instance of the TokenStore.
     * @param providerSettingsFactory An instance of the OAuth2ProviderSettingsFactory.
     * @param urisFactory An instance of the OAuth2UrisFactory.
     * @param identityManager An instance of the IdentityManager.
     */
    @Inject
    public AccessTokenService(Map<String, GrantTypeHandler> grantTypeHandlers,
            final ClientAuthenticator clientAuthenticator, final TokenStore tokenStore,
            final OAuth2ProviderSettingsFactory providerSettingsFactory, OAuth2UrisFactory urisFactory,
            IdentityManager identityManager) {
        this.grantTypeHandlers = grantTypeHandlers;
        this.clientAuthenticator = clientAuthenticator;
        this.tokenStore = tokenStore;
        this.providerSettingsFactory = providerSettingsFactory;
        this.urisFactory = urisFactory;
        this.identityManager = identityManager;
    }

    /**
     * Handles a request for access token(s) by a OAuth2 client, validates that the request is valid and contains the
     * required parameters, checks that the authorization code on the request is valid and has not expired, or been
     * previously used.
     *
     * @param request The OAuth2Request for the client requesting an access token. Must not be {@code null}.
     * @return An AccessToken.
     * @throws InvalidGrantException If the requested grant on the request is not supported.
     * @throws RedirectUriMismatchException If the redirect uri on the request does not match the redirect uri
     *          registered for the client.
     * @throws InvalidClientException If either the request does not contain the client's id or the client fails to be
     *          authenticated.
     * @throws InvalidRequestException If the request is missing any required parameters or is otherwise malformed.
     * @throws InvalidCodeException If the authorization code on the request has expired.
     * @throws ServerException If any internal server error occurs.
     * @throws UnauthorizedClientException If the client's authorization fails.
     * @throws IllegalArgumentException If the request is missing any required parameters.
     * @throws NotFoundException If the realm does not have an OAuth 2.0 provider service.
     */
    public AccessToken requestAccessToken(OAuth2Request request) throws RedirectUriMismatchException,
            InvalidClientException, InvalidRequestException, InvalidCodeException,
            InvalidGrantException, ServerException, UnauthorizedClientException, InvalidScopeException,
            NotFoundException, AuthorizationPendingException, ExpiredTokenException, AuthorizationDeclinedException, BadRequestException {
        final String grantType = request.getParameter(GRANT_TYPE);
        final GrantTypeHandler grantTypeHandler = grantTypeHandlers.get(grantType);
        if (grantTypeHandler == null) {
            throw new InvalidGrantException("Unknown Grant Type, " + grantType);
        }
        return grantTypeHandler.handle(request);
    }

    /**
     * Handles a request to refresh an already issued access token for a OAuth2 client, validates that the request is
     * valid and contains the  required parameters, checks that the refresh token on the request is valid and has not
     * expired, or been previously used to refresh an access token.
     *
     * @param request The OAuth2Request for the client requesting an refresh token. Must not be {@code null}.
     * @return An Access Token.
     * @throws InvalidClientException If either the request does not contain the client's id or the client fails to be
     *          authenticated.
     * @throws InvalidRequestException If the request is missing any required parameters or is otherwise malformed.
     * @throws BadRequestException If the request is malformed.
     * @throws ServerException If any internal server error occurs.
     * @throws ExpiredTokenException If the access token or refresh token has expired.
     * @throws IllegalArgumentException If the request is missing any required parameters.
     * @throws InvalidGrantException If the given token is not a refresh token.
     * @throws NotFoundException If the realm does not have an OAuth 2.0 provider service.
     */
    public AccessToken refreshToken(OAuth2Request request) throws InvalidClientException, InvalidRequestException,
            BadRequestException, ServerException, ExpiredTokenException, InvalidGrantException,
            InvalidScopeException, NotFoundException {

        Reject.ifTrue(isEmpty(request.<String>getParameter(REFRESH_TOKEN)), "Missing parameter, 'refresh_token'");

        final OAuth2ProviderSettings providerSettings = providerSettingsFactory.get(request);
        final OAuth2Uris uris = urisFactory.get(request);
        final ClientRegistration clientRegistration = clientAuthenticator.authenticate(request,
                uris.getTokenEndpoint());

        final String tokenId = request.getParameter(REFRESH_TOKEN);
        final RefreshToken refreshToken = tokenStore.readRefreshToken(request, tokenId);

        if (refreshToken == null) {
            logger.error("Refresh token does not exist for id: " + tokenId);
            throw new InvalidRequestException("RefreshToken does not exist");
        }

        AuditRequestContext.putProperty(OAUTH2_GRANT.toString(), refreshToken.getAuditTrackingId());

        if (!refreshToken.getClientId().equalsIgnoreCase(clientRegistration.getClientId())) {
            logger.error("Refresh Token was issued to a different client id: " + clientRegistration.getClientId());
            throw new InvalidRequestException("Token was issued to a different client");
        }

        if (refreshToken.isExpired()) {
            logger.warn("Refresh Token is expired for id: " + refreshToken.getTokenId());
            throw new InvalidGrantException("grant is invalid");
        }

        AMIdentity id = null;
        try {
            id = identityManager.getResourceOwnerIdentity(refreshToken.getResourceOwnerId(),
                    refreshToken.getRealm());
        } catch (UnauthorizedClientException ex) {
            // The detailed debug log has been output in IdentityManager.
            logger.debug("Error in validating the resource owner of this refresh token.", ex);
        }
        if (id == null) { // it includes the case that the resource owner is inactive.
            logger.warn("Resource owner({}) of this refresh token is not valid any more",
                    refreshToken.getResourceOwnerId());
            throw new InvalidRequestException("Resource owner of this refresh token is not valid any more.");
        }

        final Set<String> scope = splitScope(request.<String>getParameter(SCOPE));
        final String grantType = request.getParameter(GRANT_TYPE);

        final Set<String> tokenScope;
        if (refreshToken.getScope() != null) {
            tokenScope = new TreeSet<String>(refreshToken.getScope());
        } else {
            tokenScope = new TreeSet<String>();
        }

        final Set<String> validatedScope = providerSettings.validateRefreshTokenScope(clientRegistration,
                Collections.unmodifiableSet(scope), Collections.unmodifiableSet(tokenScope),
                request);

        final String validatedClaims = providerSettings.validateRequestedClaims(refreshToken.getClaims());

        RefreshToken newRefreshToken = null;
        if (providerSettings.issueRefreshTokensOnRefreshingToken()) {
            newRefreshToken = tokenStore.createRefreshToken(grantType, clientRegistration.getClientId(),
                    refreshToken.getResourceOwnerId(), refreshToken.getRedirectUri(), refreshToken.getScope(), request,
                    validatedClaims, refreshToken.getAuthGrantId());

            tokenStore.deleteRefreshToken(request, refreshToken.toString());
        }

        final AccessToken accessToken = tokenStore.createAccessToken(grantType, OAuth2Constants.Bearer.BEARER, null,
                refreshToken.getResourceOwnerId(), clientRegistration.getClientId(), refreshToken.getRedirectUri(),
                validatedScope, newRefreshToken == null ? refreshToken : newRefreshToken,
                null, validatedClaims, request);

        if (newRefreshToken != null) {
            accessToken.addExtraData(REFRESH_TOKEN, newRefreshToken.toString());
        }

        providerSettings.additionalDataToReturnFromTokenEndpoint(accessToken, request);

        if (validatedScope != null && !validatedScope.isEmpty()) {
            accessToken.addExtraData(SCOPE, joinScope(validatedScope));
        }

        return accessToken;
    }
}
