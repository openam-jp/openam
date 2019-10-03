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
 * Copyright 2019 Open Source Solution Technology Corporation
 */

package org.forgerock.openam.core.rest.server;

import static org.assertj.core.api.Assertions.*;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.utils.CollectionUtils.*;
import static org.mockito.BDDMockito.*;
import static org.mockito.Mockito.mock;

import java.util.concurrent.ExecutionException;

import com.sun.identity.shared.debug.Debug;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.openam.services.RestSecurityProvider;
import org.forgerock.openam.shared.security.whitelist.RedirectUrlValidator;
import org.forgerock.openam.shared.security.whitelist.ValidDomainExtractor;
import org.forgerock.openam.sm.config.ConsoleConfigHandler;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ServerInfoResourceTest {
    
    public static final String VALID_URL = "http://valid.example.co.jp/path";
    public static final String INVALID_URL = "http://invalid.example.co.jp/path";
    
    private final Debug mockDebug = mock(Debug.class);

    private ConsoleConfigHandler mockConfigHandler;
    private RestSecurityProvider mockRestSecurityProvider;
    private ValidDomainExtractor<String> mockDomainExtractor;

    private ServerInfoResource serverInfoResource;
    
    @BeforeMethod
    public void setUp() {
        
        mockConfigHandler = mock(ConsoleConfigHandler.class);
        mockRestSecurityProvider = mock(RestSecurityProvider.class);
        mockDomainExtractor = mock(ValidDomainExtractor.class);
        
        RedirectUrlValidator<String> urlValidator = 
                new RedirectUrlValidator<String>(mockDomainExtractor);
        
        serverInfoResource = new ServerInfoResource(mockDebug, mockConfigHandler, 
                mockRestSecurityProvider, urlValidator);
    }

    @Test
    public void validateGotoShouldReturnUrlWhenNoSetting() throws InterruptedException, ExecutionException {
        
        // Given
        JsonValue requestJson = json(object(field("goto", VALID_URL)));
        Context context = mock(Context.class);
        ActionRequest request = mock(ActionRequest.class);
        given(request.getAction()).willReturn("validateGoto");
        given(request.getContent()).willReturn(requestJson);
        given(mockDomainExtractor.extractValidDomains(any(String.class))).willReturn(null);

        // When
        Promise<ActionResponse, ResourceException> promise = 
                serverInfoResource.actionCollection(context, request);

        // Then
        assertThat(promise.get().getJsonContent().get("validatedUrl").asString()).isEqualTo(VALID_URL);
    }
    
    @Test
    public void validateGotoShouldReturnUrlWithValidUrl() throws InterruptedException, ExecutionException {
        
        // Given
        JsonValue requestJson = json(object(field("goto", VALID_URL)));
        Context context = mock(Context.class);
        ActionRequest request = mock(ActionRequest.class);
        given(request.getAction()).willReturn("validateGoto");
        given(request.getContent()).willReturn(requestJson);
        given(mockDomainExtractor.extractValidDomains(any(String.class))).willReturn(asSet(VALID_URL));

        // When
        Promise<ActionResponse, ResourceException> promise = 
                serverInfoResource.actionCollection(context, request);

        // Then
        assertThat(promise.get().getJsonContent().get("validatedUrl").asString()).isEqualTo(VALID_URL);
    }
    
    @Test
    public void validateGotoShouldReturnNullWithInvalidUrl() throws InterruptedException, ExecutionException {
        
        // Given
        JsonValue requestJson = json(object(field("goto", INVALID_URL)));
        Context context = mock(Context.class);
        ActionRequest request = mock(ActionRequest.class);
        given(request.getAction()).willReturn("validateGoto");
        given(request.getContent()).willReturn(requestJson);
        given(mockDomainExtractor.extractValidDomains(any(String.class))).willReturn(asSet(VALID_URL));

        // When
        Promise<ActionResponse, ResourceException> promise = 
                serverInfoResource.actionCollection(context, request);

        // Then
        assertThat(promise.get().getJsonContent().get("validatedUrl").asString()).isEqualTo(null);
    }

}
