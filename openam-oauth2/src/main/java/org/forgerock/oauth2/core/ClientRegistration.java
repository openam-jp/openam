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
 * Portions Copyrighted 2019 Open Source Solution Technology Corporation.
 */

package org.forgerock.oauth2.core;

import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.forgerock.oauth2.core.exceptions.ServerException;

/**
 * Models a client registration in the OAuth2 provider.
 *
 * @since 12.0.0
 * @supported.all.api
 */
public interface ClientRegistration {

    /**
     * Gets the registered redirect uris for the client.
     *
     * @return The redirect uris.
     */
    Set<URI> getRedirectUris();

    /**
     * Gets the registered post logout redirect uris for the client.
     *
     * @return The redirect uris.
     */
    Set<URI> getPostLogoutRedirectUris();

    /**
     * Gets the allowed response types.
     *
     * @return The allowed response types.
     */
    Set<String> getAllowedResponseTypes();

    /**
     * Gets the client's identifier.
     *
     * @return The client's id.
     */
    String getClientId();

    /**
     * Gets the client's secret.
     *
     * @return The client's secret.
     */
    String getClientSecret();

    /**
     * Gets the type of access token the client requires.
     *
     * @return The access token type.
     */
    String getAccessTokenType();

    /**
     * Gets the display name of the client in the specified locale.
     *
     * @param locale The locale.
     * @return The display name.
     */
    String getDisplayName(Locale locale);

    /**
     * Gets the display description of the client in the specified locale.
     *
     * @param locale The locale.
     * @return The display description.
     */
    String getDisplayDescription(Locale locale);

    /**
     * Gets the display descriptions for the allowed and default scopes combined, in the specified locale.
     *
     * @param locale The locale.
     * @return The descriptions of the allowed and default scopes combined.
     */
    Map<String, String> getScopeDescriptions(Locale locale) throws ServerException;

    /**
     * Gets the display descriptions for the allowed and default scopes combined, in the specified locale.
     *
     * @param locale The locale.
     * @return The descriptions of the allowed and default scopes combined.
     */
    Map<String, String> getClaimDescriptions(Locale locale) throws ServerException;

    /**
     * Gets the default scopes configured for the client.
     *
     * @return The default scopes.
     */
    Set<String> getDefaultScopes();

    /**
     * Gets the allowed scopes configured for the client.
     *
     * @return The allowed scopes.
     */
    Set<String> getAllowedScopes();

    /**
     * Gets whether the client is confidential or not.
     *
     * @return {@code true} if the client is confidential.
     */
    boolean isConfidential();

    /**
     * Gets the client's session URI.
     *
     * @return The client's session URI.
     */
    String getClientSessionURI();

    /**
     * Gets the subject type of this client. PAIRWISE or PUBLIC.
     */
    String getSubjectType();

    /**
     * Verifies that the supplied jwt is signed by this client.
     */
    boolean verifyJwtIdentity(OAuth2Jwt jwt);

    /**
     * Gets whether or not the client wants the OAuth2 implementation to skip asking the resource owner for consent.
     *
     * @return true if the client is configured to skip resource owner consent.
     */
    boolean isConsentImplied();

     /**
      * Gets whether or not Policy Based Endpoint Protection is enabled.
      *
      * @return true if enabled.
      */
    boolean isPolicyBasedProtectionEnabled();

}
