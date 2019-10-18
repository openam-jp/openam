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
 * Portions Copyrighted 2019 Open Source Solution Technology Corporation
 */

package org.forgerock.openam.oauth2.saml2.core;

import com.google.inject.AbstractModule;
import com.google.inject.multibindings.MapBinder;
import org.forgerock.guice.core.GuiceModule;
import org.forgerock.oauth2.core.GrantTypeHandler;
import org.forgerock.openam.oauth2.OAuth2Constants;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Singleton;
import com.google.inject.Provides;
import com.google.inject.multibindings.Multibinder;

import org.forgerock.oauth2.core.SAML2BearerRequestValidator;
import org.forgerock.oauth2.core.PolicyBasedDenyRequestValidatorImpl;

@GuiceModule
public class OAuth2Saml2GuiceModule extends AbstractModule {

    @Override
    protected void configure() {
        MapBinder<String, GrantTypeHandler> grantTypeHandlers =
                MapBinder.newMapBinder(binder(), String.class, GrantTypeHandler.class);
        grantTypeHandlers.addBinding(OAuth2Constants.TokenEndpoint.SAML2_BEARER).to(Saml2GrantTypeHandler.class);
        
        final Multibinder<SAML2BearerRequestValidator> SAML2BearerRequestValidators =
                Multibinder.newSetBinder(binder(), SAML2BearerRequestValidator.class);
        SAML2BearerRequestValidators.addBinding().to(PolicyBasedDenyRequestValidatorImpl.class);

    }
    
    @Inject
    @Provides
    @Singleton
    List<SAML2BearerRequestValidator> getSAML2BearerRequestValidators(
            final Set<SAML2BearerRequestValidator> SAML2BearerRequestValidators) {
        return new ArrayList<>(SAML2BearerRequestValidators);
    }
    
}
