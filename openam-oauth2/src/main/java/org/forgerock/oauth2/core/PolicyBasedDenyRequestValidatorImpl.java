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
 * Copyright (c) 2019 Open Source Solution Technology Corporation
 */

package org.forgerock.oauth2.core;

import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the request validator for the OAuth2 grant types.
 * If policy based endpoint protection is enabled, ClientCredentials, PasswordCredentials
 * and SAML2.0 Bearer grant types are not permitted.
 *
 */
public class PolicyBasedDenyRequestValidatorImpl implements ClientCredentialsRequestValidator, 
        PasswordCredentialsRequestValidator, SAML2BearerRequestValidator {

    private final Logger logger = LoggerFactory.getLogger("OAuth2Factory");

    /**
     * {@inheritDoc}
     */
    @Override
    public void validateRequest(OAuth2Request request, ClientRegistration clientRegistration)
            throws UnauthorizedClientException {

        if (clientRegistration.isPolicyBasedProtectionEnabled()) {
            logger.error("Under policy based endpoint protection, this grant type is not permitted.");
            throw new UnauthorizedClientException("Policy based endpoint protection is enabled.");
        }
    }
}
