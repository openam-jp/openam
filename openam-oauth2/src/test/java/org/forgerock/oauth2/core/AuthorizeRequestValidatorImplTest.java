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
 * Copyright 2016 ForgeRock AS.
 * Portions Copyrighted 2018 OGIS-RI Co., Ltd.
 * Portions copyright 2019 Open Source Solution Technology Corporation
 */

package org.forgerock.oauth2.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.CLIENT_ID;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.REDIRECT_URI;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.RESPONSE_TYPE;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnsupportedResponseTypeException;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * @since 14.0.0
 */
public class AuthorizeRequestValidatorImplTest {

    public static final String REGISTERED_URI = "http://registereduri";

    public static final String NO_REGISTERED_URI = "http://noregistereduri";

    private ClientRegistrationStore clientRegistrationStore;

    private ClientRegistration clientRegistration;

    private AuthorizeRequestValidatorImpl validator;
    
    private RedirectUriValidator redirectUriValidator;

    private OAuth2ProviderSettingsFactory providerSettingsFactory;

    private OAuth2ProviderSettings providerSettings;

    private ResponseTypeValidator responseTypeValidator;

    private Set<URI> uriSetWithMany;

    private Set<URI> uriSetWithOne;

    @BeforeMethod
    public void setup() throws NotFoundException, UnsupportedResponseTypeException, ServerException {
        clientRegistrationStore = mock(ClientRegistrationStore.class);
        clientRegistration = mock(ClientRegistration.class);
        Set<String> allowedResponseTypesInClient = new HashSet<String>();
        allowedResponseTypesInClient.add("code");
        given(clientRegistration.getAllowedResponseTypes()).willReturn(allowedResponseTypesInClient);

        providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        providerSettings = mock(OAuth2ProviderSettings.class);
        given(providerSettingsFactory.get(Mockito.any(OAuth2Request.class))).willReturn(providerSettings);
        Map<String, ResponseTypeHandler> allowedResponseTypesInProvider = new HashMap<String, ResponseTypeHandler>();
        allowedResponseTypesInProvider.put("code", mock(ResponseTypeHandler.class));
        given(providerSettings.getAllowedResponseTypes()).willReturn(allowedResponseTypesInProvider);

        redirectUriValidator = new RedirectUriValidator();
        responseTypeValidator = new ResponseTypeValidator();

        validator = new AuthorizeRequestValidatorImpl(clientRegistrationStore, redirectUriValidator, providerSettingsFactory, responseTypeValidator);

        uriSetWithMany = new HashSet<>(Arrays.asList(new URI[]{URI.create("http://one"),
                URI.create("http://two"), URI.create("http://three"), URI.create(REGISTERED_URI)}));

        uriSetWithOne = new HashSet<>(Arrays.asList(new URI[]{URI.create(REGISTERED_URI)}));
    }
    
    @Test
    public void shouldValidateRedirectUriWithManyRegisteredUris() throws NotFoundException, InvalidClientException, InvalidRequestException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {
        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn(REGISTERED_URI);
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(uriSetWithMany);
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        verify(request).setValidRedirectUri(REGISTERED_URI);
    }

    @Test(expectedExceptions = RedirectUriMismatchException.class)
    public void shouldThrowExceptionWhenNoRegisterdUriWithManyRegisteredUris() throws NotFoundException, InvalidClientException, InvalidRequestException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {

        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn(NO_REGISTERED_URI);
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(uriSetWithMany);
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        //should throw redirect_uri mismatch exception

    }


    @Test
    public void shouldValidateRedirectUriWithOneRegisteredUris() throws NotFoundException, InvalidClientException, InvalidRequestException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {
        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn(REGISTERED_URI);
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(uriSetWithOne);
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        verify(request).setValidRedirectUri(REGISTERED_URI);
    }


    @Test(expectedExceptions = RedirectUriMismatchException.class)
    public void shouldThrowExceptionWhenNoRegisterdUriWithOneRegisteredUris() throws NotFoundException, InvalidClientException, InvalidRequestException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {

        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn(NO_REGISTERED_URI);
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(uriSetWithOne);
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        //should throw redirect_uri mismatch exception

    }


    @Test
    public void shouldReturnRegisterdUriWhenNoRedirectUriWithOneRegisteredUri() throws InvalidRequestException, NotFoundException, InvalidClientException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {

        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn(null);
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(uriSetWithOne);
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        verify(request).setValidRedirectUri(REGISTERED_URI);
    }


    @Test(expectedExceptions = InvalidRequestException.class)
    public void shouldThrowExceptionWhenRedirectUriWithNullRegisteredUri() throws NotFoundException, InvalidClientException, InvalidRequestException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {

        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn("http://someuri");
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(null);
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        //should throw invalid request  exception

    }

    @Test(expectedExceptions = InvalidRequestException.class)
    public void shouldThrowExceptionWhenRedirectUriWithEmptyRegisteredUri() throws NotFoundException, InvalidClientException, InvalidRequestException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {

        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn("http://someuri");
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(new HashSet<URI>());
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        //should throw invalid request  exception

    }

    @Test(expectedExceptions = InvalidRequestException.class)
    public void shouldThrowExceptionWhenNoParameterAndNullRegisteredUri() throws NotFoundException, InvalidClientException, InvalidRequestException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {

        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn(null);
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(null);
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        //should throw invalid request  exception

    }

    @Test(expectedExceptions = InvalidRequestException.class)
    public void shouldThrowExceptionWhenNoParameterAndManyRegisteredUri() throws NotFoundException, InvalidClientException, InvalidRequestException, RedirectUriMismatchException, UnsupportedResponseTypeException, ServerException {

        //given
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter(REDIRECT_URI)).willReturn(null);
        given(request.<String>getParameter(CLIENT_ID)).willReturn("client_id");
        given(request.<String>getParameter(RESPONSE_TYPE)).willReturn("code");
        given(clientRegistration.getRedirectUris()).willReturn(uriSetWithMany);
        given(clientRegistrationStore.get("client_id", request)).willReturn(clientRegistration);


        //when
        validator.validateRequest(request);


        //then
        //should throw invalid request  exception

    }

    // TODO: We should add tests for response_type verification

}
