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

package org.forgerock.oauth2.restlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.CsrfProtection;
import org.forgerock.oauth2.core.DeviceCode;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.ResourceOwner;
import org.forgerock.oauth2.core.ResourceOwnerSessionValidator;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.xui.XUIState;
import org.mockito.ArgumentMatchers;
import org.restlet.Context;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.ClientInfo;
import org.restlet.engine.adapter.HttpRequest;
import org.restlet.ext.freemarker.TemplateRepresentation;
import org.restlet.ext.servlet.internal.ServletCall;
import org.restlet.routing.Router;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Tests that the OAuth2 device verification endpoint acts on the consent decision the resource owner made on
 * the consent page, rather than on one a link put in the query string the page posts back to.
 *
 * @see <a href="https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-545c-rm35-2jj2">
 *     GHSA-545c-rm35-2jj2</a>
 */
public class DeviceCodeVerificationResourceTest {

    private static final String USER_CODE = "BDCT-HQKD";
    private static final String CLIENT_ID = "attacker_client";

    private DeviceCodeVerificationResource resource;
    private OAuth2Request o2request;
    private DeviceCode deviceCode;
    private TokenStore tokenStore;
    private CsrfProtection csrfProtection;
    private OAuth2ProviderSettings providerSettings;
    private AuthorizationService authorizationService;

    @BeforeMethod
    public void setup() throws Exception {
        // A request that arrived through the servlet container, as every request to this endpoint does
        ServletCall servletCall = mock(ServletCall.class);
        when(servletCall.getRequest()).thenReturn(mock(HttpServletRequest.class));
        HttpRequest httpRequest = mock(HttpRequest.class);
        when(httpRequest.getHttpCall()).thenReturn(servletCall);
        Request restletRequest = httpRequest;
        when(restletRequest.getAttributes()).thenReturn(new ConcurrentHashMap<String, Object>());
        when(restletRequest.getClientInfo()).thenReturn(new ClientInfo());

        o2request = mock(OAuth2Request.class);
        when(o2request.getRequest()).thenReturn(restletRequest);
        when(o2request.<String>getParameter(OAuth2Constants.DeviceCode.USER_CODE)).thenReturn(USER_CODE);
        when(o2request.<String>getParameter(OAuth2Constants.Params.CLIENT_ID)).thenReturn(CLIENT_ID);
        when(o2request.<String>getParameter(OAuth2Constants.Params.SCOPE)).thenReturn("openid");

        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        when(requestFactory.create(restletRequest)).thenReturn(o2request);

        deviceCode = new DeviceCode("DEVICE-CODE", USER_CODE, null, CLIENT_ID, null, null, null, null, null,
                null, null, null, null, System.currentTimeMillis() + 60000L,
                Collections.singleton("openid"), "/", null, null, "audit-tracking-id");
        tokenStore = mock(TokenStore.class);
        when(tokenStore.readDeviceCode(USER_CODE, o2request)).thenReturn(deviceCode);

        providerSettings = mock(OAuth2ProviderSettings.class);
        OAuth2ProviderSettingsFactory providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        when(providerSettingsFactory.get(o2request)).thenReturn(providerSettings);

        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        ClientRegistrationStore clientRegistrationStore = mock(ClientRegistrationStore.class);
        when(clientRegistrationStore.get(CLIENT_ID, o2request)).thenReturn(clientRegistration);

        ResourceOwnerSessionValidator resourceOwnerSessionValidator = mock(ResourceOwnerSessionValidator.class);
        ResourceOwner resourceOwner = mock(ResourceOwner.class);
        when(resourceOwner.getId()).thenReturn("victim");
        when(resourceOwnerSessionValidator.validate(o2request)).thenReturn(resourceOwner);

        // The consent page's own submission carries a valid csrf value; what is under test is where the
        // decision is read from, not whether the request is forged
        csrfProtection = mock(CsrfProtection.class);
        when(csrfProtection.isCsrfAttack(o2request)).thenReturn(false);

        authorizationService = mock(AuthorizationService.class);

        OAuth2Utils oAuth2Utils = mock(OAuth2Utils.class);
        when(oAuth2Utils.join(any(Iterable.class), anyString())).thenReturn("");

        BaseURLProvider baseUrlProvider = mock(BaseURLProvider.class);
        when(baseUrlProvider.getRootURL(nullable(HttpServletRequest.class)))
                .thenReturn("http://openam.example.com:8080/openam");
        BaseURLProviderFactory baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        when(baseURLProviderFactory.get(ArgumentMatchers.<String>any())).thenReturn(baseUrlProvider);

        resource = new DeviceCodeVerificationResource(mock(XUIState.class), mock(Router.class),
                baseURLProviderFactory, mock(OAuth2Representation.class), tokenStore, requestFactory,
                authorizationService, providerSettingsFactory, mock(ExceptionHandler.class),
                resourceOwnerSessionValidator, clientRegistrationStore, oAuth2Utils, csrfProtection);
        resource = spy(resource);
        doReturn(restletRequest).when(resource).getRequest();
        doReturn(new Response(restletRequest)).when(resource).getResponse();

        // The endpoint reaches its template factory through the Restlet context
        TemplateFactory templateFactory = mock(TemplateFactory.class);
        when(templateFactory.getTemplateRepresentation(anyString())).thenReturn(mock(TemplateRepresentation.class));
        Context context = new Context();
        context.getAttributes().put(TemplateFactory.class.getName(), templateFactory);
        doReturn(context).when(resource).getContext();
    }

    /**
     * The consent page posts back to the URL it was served from, so a link to
     * {@code ?user_code=...&decision=allow} puts {@code decision=allow} in the query string of the resource
     * owner's own submission. {@code getParameter} gives the query priority, which would turn the "Deny" they
     * clicked into an approved device code.
     */
    @Test
    public void shouldTakeTheConsentDecisionFromTheBodyRatherThanTheQueryString() throws Exception {
        //given the resource owner clicked "Deny" without ticking "save", on a page whose URL says otherwise
        when(o2request.getBodyParameter("decision")).thenReturn("deny");
        when(o2request.<String>getParameter("decision")).thenReturn("allow");
        when(o2request.<String>getParameter("save_consent")).thenReturn("on");

        //when
        resource.verify(null);

        //then what the user clicked is what is acted on, and nothing is remembered
        assertThat(deviceCode.isAuthorized()).isFalse();
        verify(providerSettings, never()).saveConsent(ArgumentMatchers.<ResourceOwner>any(),
                ArgumentMatchers.<String>any(), ArgumentMatchers.<Set<String>>any());
    }

    /**
     * A decision that only the query string carries is no decision at all: the endpoint asks for consent
     * instead of recording one.
     */
    @Test
    public void shouldNotTakeAConsentDecisionFromTheQueryString() throws Exception {
        //given a link carrying a decision, and a submission that carries none
        when(o2request.<String>getParameter("decision")).thenReturn("allow");
        when(o2request.<String>getParameter("save_consent")).thenReturn("on");

        //when
        resource.verify(null);

        //then
        verify(authorizationService).authorize(o2request);
        verify(providerSettings, never()).saveConsent(ArgumentMatchers.<ResourceOwner>any(),
                ArgumentMatchers.<String>any(), ArgumentMatchers.<Set<String>>any());
        assertThat(deviceCode.isAuthorized()).isFalse();
        verify(tokenStore, never()).updateDeviceCode(any(DeviceCode.class), any(OAuth2Request.class));
    }

    /**
     * Whether to remember the decision has to come from the same place as the decision itself - a link whose
     * query string says {@code save_consent=on} must not turn a one-off "Allow" into a grant recorded
     * permanently.
     */
    @Test
    public void shouldNotSaveConsentFromTheQueryString() throws Exception {
        //given the resource owner clicked "Allow" without ticking "save", on a page whose URL says save_consent=on
        when(o2request.getBodyParameter("decision")).thenReturn("allow");
        when(o2request.<String>getParameter("save_consent")).thenReturn("on");

        //when
        resource.verify(null);

        //then the device code is authorized, and nothing is remembered
        assertThat(deviceCode.isAuthorized()).isTrue();
        verify(providerSettings, never()).saveConsent(ArgumentMatchers.<ResourceOwner>any(),
                ArgumentMatchers.<String>any(), ArgumentMatchers.<Set<String>>any());
    }

    /**
     * The positive side of the pair above: an "Allow" with "save" ticked, both in the body, has to record the
     * grant. Without this, the mutant that reads {@code save_consent} as always false stays green.
     */
    @Test
    public void shouldSaveConsentFromTheBody() throws Exception {
        //given the resource owner clicked "Allow" with "save" ticked
        when(o2request.getBodyParameter("decision")).thenReturn("allow");
        when(o2request.getBodyParameter("save_consent")).thenReturn("on");

        //when
        resource.verify(null);

        //then
        assertThat(deviceCode.isAuthorized()).isTrue();
        assertThat(deviceCode.getResourceOwnerId()).isEqualTo("victim");
        verify(tokenStore).updateDeviceCode(deviceCode, o2request);
        // any() rather than anyString(): the mocked client registration's client id is null
        verify(providerSettings).saveConsent(ArgumentMatchers.<ResourceOwner>any(),
                ArgumentMatchers.<String>any(), ArgumentMatchers.<Set<String>>any());
    }
}
