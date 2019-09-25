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
 * Portions Copyrighted 2018 OGIS-RI Co., Ltd.
 */

package org.forgerock.oauth2.restlet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.*;

import java.util.Collections;

import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.AuthorizationToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.xui.XUIState;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.representation.EmptyRepresentation;
import org.restlet.routing.Router;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class AuthorizeResourceTest {

    private AuthorizeResource resource;
    private OAuth2Request o2request;
    private Request request;
    private Response response;
    private AuthorizationService service;
    private AuthorizeRequestHook hook;
    private AuthorizationToken authToken = new AuthorizationToken(Collections.singletonMap("fred", "fred"), false);
    private XUIState xuiState;

    @BeforeMethod
    public void setup() throws Exception {
        OAuth2Representation representation = mock(OAuth2Representation.class);
        OAuth2RequestFactory oauth2RequestFactory = mock(OAuth2RequestFactory.class);
        o2request = mock(OAuth2Request.class);
        request = mock(Request.class);
        response = mock(Response.class);
        hook = mock(AuthorizeRequestHook.class);
        service = mock(AuthorizationService.class);
        xuiState = mock(XUIState.class);

        when(oauth2RequestFactory.create(request)).thenReturn(o2request);

        resource = new AuthorizeResource(oauth2RequestFactory, service, null, representation,
                CollectionUtils.asSet(hook), xuiState, mock(Router.class), null);
        resource = spy(resource);
        doReturn(request).when(resource).getRequest();
        doReturn(response).when(resource).getResponse();
    }

    @Test
    public void shouldCallHooksInGet() throws Exception {
        //given
        when(service.authorize(o2request)).thenReturn(authToken);

        //when
        resource.authorize();

        //then
        verify(hook).beforeAuthorizeHandling(o2request, request, response);
        verify(hook).afterAuthorizeSuccess(o2request, request, response);
    }

    @Test
    public void shouldCallHooksInPost() throws Exception {
        //given
        when(service.authorize(o2request)).thenReturn(authToken);

        //when
        resource.authorize(new EmptyRepresentation());

        //then
        verify(hook).beforeAuthorizeHandling(o2request, request, response);
        verify(hook).afterAuthorizeSuccess(o2request, request, response);
    }

    @Test
    public void shouldNotRedirectWhenMissingClientIdInGet() throws Exception {
        // given
        when(o2request.getParameter("redirect_uri")).thenReturn("https://www.example.com");
        doThrow(new IllegalArgumentException("Missing parameter, 'client_id'")).when(service).authorize(o2request);

        // Using try~catch block because want to inspect the Exception properties
        try {
            // when
            resource.authorize();
        } catch (OAuth2RestletException e) {
            // then
            assertEquals("invalid_request", e.getError());
            assertNull(e.getRedirectUri());
        }
    }

    @Test
    public void shouldNotRedirectWhenMissingResponseTypeInGet() throws Exception {
        // given
        when(o2request.getParameter("redirect_uri")).thenReturn("https://www.example.com");
        doThrow(new IllegalArgumentException("Missing parameter, 'response_type'")).when(service).authorize(o2request);

        // Using try~catch block because want to inspect the Exception properties
        try {
            // when
            resource.authorize();
        } catch (OAuth2RestletException e) {
            // then
            assertEquals("invalid_request", e.getError());
            assertNull(e.getRedirectUri());
        }
    }

    @Test
    public void shouldNotRedirectWhenBadRequestExceptionInPost() throws Exception {
        // given
        when(o2request.getParameter("redirect_uri")).thenReturn("https://www.example.com");
        doThrow(new BadRequestException("Test Exception")).when(service).authorize(o2request, false, false);

        // Using try~catch block because want to inspect the Exception properties
        try {
            // when
            resource.authorize(new EmptyRepresentation());
        } catch (OAuth2RestletException e) {
            // then
            assertEquals("bad_request", e.getError());
            assertNull(e.getRedirectUri());
        }
    }
}