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

package jp.co.osstech.openam.authentication.modules.webauthn;

import org.forgerock.guice.core.GuiceModule;

import com.google.inject.AbstractModule;

/**
 * The GuiceModule class configures the guice framework for the WebAuthn Auth module.
 */
@GuiceModule
public class WebAuthnGuiceModule extends AbstractModule {

    @Override
    protected void configure() {
        bind(WebAuthnValidator.class).toInstance(new WebAuthn4JValidatorImpl());
    }
}
