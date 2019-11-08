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

import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.shared.debug.Debug;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

/**
 * Interface for WebAuthn Validation.
 */
public interface WebAuthnValidator {
    
    /**
     * Generate challenge byte.
     * @return The challenge byte.
     */
    public byte[] generateChallenge();

    /**
     * Validate javascript credential.create() response.
     * 
     * @param config The configuration for the validation.
     * @param responseJson The response object.
     * @param userHandleIdBytes The user handle.
     * @param debug Debug instance.
     * @return WebAuthnAuthenticator instance to store.
     * @throws AuthLoginException
     */
    WebAuthnAuthenticator validateCreateResponse(WebAuthnValidatorConfig config, WebauthnJsonCallback responseJson,
            byte[] userHandleIdBytes, Debug debug) throws AuthLoginException;

    /**
     * Validate javascript credential.get() response.
     * If this method succeeds, the counter of the authenticator will be set.
     * 
     * @param config The configuration for the validation.
     * @param responseJson  The response object.
     * @param amAuthenticator WebAuthnAuthenticator instance.
     * @param debug Debug instance.
     * @throws AuthLoginException
     */
    void validateGetResponse(WebAuthnValidatorConfig config, WebauthnJsonCallback responseJson,
            WebAuthnAuthenticator amAuthenticator, Debug debug) throws AuthLoginException;

}
