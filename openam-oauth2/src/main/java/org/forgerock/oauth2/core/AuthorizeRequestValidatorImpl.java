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
 * Copyright 2014-2016 ForgeRock AS.
 * Portions Copyrighted 2018 Open Source Solution Technology Corporation
 * Portions Copyrighted 2019 OGIS-RI Co., Ltd.
 */

package org.forgerock.oauth2.core;

import static org.forgerock.openam.oauth2.OAuth2Constants.Params.*;

import java.net.URI;
import java.util.Set;

import static org.forgerock.oauth2.core.Utils.*;

import javax.inject.Inject;
import javax.inject.Singleton;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnsupportedResponseTypeException;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Constants.EndpointType;
import org.forgerock.util.Reject;

/**
 * Implementation of the request validator for the OAuth2 authorize endpoint.
 *
 * @since 12.0.0
 */
@Singleton
public class AuthorizeRequestValidatorImpl implements AuthorizeRequestValidator {

    private final ClientRegistrationStore clientRegistrationStore;
    private final RedirectUriValidator redirectUriValidator;
    private final OAuth2ProviderSettingsFactory providerSettingsFactory;
    private final ResponseTypeValidator responseTypeValidator;

    /**
     * Constructs a new AuthorizeRequestValidatorImpl instance.
     *
     * @param clientRegistrationStore An instance of the ClientRegistrationStore.
     * @param redirectUriValidator An instance of the RedirectUriValidator.
     * @param providerSettingsFactory An instance of the OAuth2ProviderSettingsFactory.
     * @param responseTypeValidator An instance of the ResponseTypeValidator.
     */
    @Inject
    public AuthorizeRequestValidatorImpl(ClientRegistrationStore clientRegistrationStore,
            RedirectUriValidator redirectUriValidator, OAuth2ProviderSettingsFactory providerSettingsFactory,
            ResponseTypeValidator responseTypeValidator) {
        this.clientRegistrationStore = clientRegistrationStore;
        this.redirectUriValidator = redirectUriValidator;
        this.providerSettingsFactory = providerSettingsFactory;
        this.responseTypeValidator = responseTypeValidator;
    }

    /**
     * {@inheritDoc}
     */
    public void validateRequest(OAuth2Request request) throws InvalidClientException, InvalidRequestException,
            RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException, NotFoundException {

        Reject.ifTrue(isEmpty(request.<String>getParameter(CLIENT_ID)), "Missing parameter, 'client_id'");
        Reject.ifTrue(isEmpty(request.<String>getParameter(RESPONSE_TYPE)), "Missing parameter, 'response_type'");

        final ClientRegistration clientRegistration = clientRegistrationStore.get(request.<String>getParameter(CLIENT_ID),
                request);

        if (request.getEndpointType() != EndpointType.END_USER_VERIFICATION_URI) {
            if (clientRegistration == null) {
                throw new InvalidRequestException("Failed to validate the client ID");
            }

            Set<URI> redirectUris = clientRegistration.getRedirectUris();

            if (isEmpty(redirectUris)) {
                throw new InvalidRequestException("Failed to resolve the redirect URI, no URI's registered");
            }

            String redirectUri = request.<String>getParameter(REDIRECT_URI);
            if (isEmpty(redirectUri) && redirectUris.size() == 1) {
                redirectUri = redirectUris.iterator().next().toString();
            }
            if (isEmpty(redirectUri)) {
                throw new InvalidRequestException("Failed to resolve the redirect URI");
            }

            redirectUriValidator.validate(clientRegistration, redirectUri);
            request.setValidRedirectUri(redirectUri);
        }

        responseTypeValidator.validate(clientRegistration,
                splitResponseType(request.<String>getParameter(RESPONSE_TYPE)), providerSettingsFactory.get(request));
    }
}
