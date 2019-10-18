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

/**
 * Request validator for the OAuth2 SAML2.0 Bearer grant.
 * Request validators validate that the specified OAuth2 request is valid by checking that the request contains all of
 * the required parameters.
 *
 */
public interface SAML2BearerRequestValidator {

    /**
     * Validates that the OAuth2 request contains the valid parameters for the OAuth2 SAML2.0 Bearer grant.
     *
     * @param request The OAuth2 request.  Must not be {@code null}.
     * @param clientRegistration The registration of the client making the request.
     * @throws UnauthorizedClientException If the client's authorization fails.
     */
    void validateRequest(OAuth2Request request, ClientRegistration clientRegistration)
            throws UnauthorizedClientException;
}
