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
 * Portions Copyrighted 2015 Nomura Research Institute, Ltd
 */

package org.forgerock.openam.oauth2;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.security.AccessController;
import java.util.Collections;
import java.util.Set;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.debug.Debug;

import org.forgerock.i18n.LocalizedIllegalArgumentException;
import org.forgerock.jaspi.modules.openid.resolvers.service.OpenIdResolverService;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.PEMDecoder;
import org.forgerock.oauth2.core.exceptions.ClientAuthenticationFailureFactory;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.OpenIdConnectClientRegistration;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;
import org.forgerock.services.context.Context;

/**
 * The OpenAM OAuth2 and OpenId Connect provider's store for all client registrations.
 *
 * @since 12.0.0
 */
@Singleton
public class OpenAMClientRegistrationStore implements OpenIdConnectClientRegistrationStore {

    private final Debug logger = Debug.getInstance("OAuth2Provider");
    private final RealmNormaliser realmNormaliser;
    private final PEMDecoder pemDecoder;
    private final OpenIdResolverService resolverService;
    private final OAuth2ProviderSettingsFactory providerSettingsFactory;
    private final ClientAuthenticationFailureFactory failureFactory;

    /**
     * Constructs a new OpenAMClientRegistrationStore.
     * @param realmNormaliser An instance of the RealmNormaliser.
     * @param pemDecoder A {@code PEMDecoder} instance.
     * @param failureFactory
     */
    @Inject
    public OpenAMClientRegistrationStore(RealmNormaliser realmNormaliser, PEMDecoder pemDecoder,
            @Named(OAuth2Constants.Custom.JWK_RESOLVER) OpenIdResolverService resolverService,
            OAuth2ProviderSettingsFactory providerSettingsFactory, ClientAuthenticationFailureFactory failureFactory) {
        this.realmNormaliser = realmNormaliser;
        this.pemDecoder = pemDecoder;
        this.resolverService = resolverService;
        this.providerSettingsFactory = providerSettingsFactory;
        this.failureFactory = failureFactory;
    }

    /**
     * {@inheritDoc}
     */
    public OpenIdConnectClientRegistration get(String clientId, OAuth2Request request)
            throws InvalidClientException, NotFoundException {
        try {
            final String realm = realmNormaliser.normalise(request.<String>getParameter(OAuth2Constants.Custom.REALM));
            return new OpenAMClientRegistration(getIdentity(clientId, realm, request), pemDecoder, resolverService,
                    providerSettingsFactory.get(request), failureFactory);
        } catch (org.forgerock.json.resource.NotFoundException e) {
            throw new NotFoundException(e.getMessage());
        }
    }

    /**
     * {@inheritDoc}
     */
    public OpenIdConnectClientRegistration get(String clientId, String realm, Context context)
            throws InvalidClientException, NotFoundException {
        try {
            final String normalisedRealm = realmNormaliser.normalise(realm);
            return new OpenAMClientRegistration(getIdentity(clientId, normalisedRealm), pemDecoder, resolverService,
                    providerSettingsFactory.get(normalisedRealm), failureFactory);
        } catch (org.forgerock.json.resource.NotFoundException e) {
            throw new NotFoundException(e.getMessage());
        }
    }

    private AMIdentity getIdentity(String uName, String realm) throws InvalidClientException {
        return getIdentity(uName, realm, null);
    }

    @SuppressWarnings("unchecked")
    private AMIdentity getIdentity(String uName, String realm, OAuth2Request request) throws InvalidClientException {
        final SSOToken token = AccessController.doPrivileged(AdminTokenAction.getInstance());
        final AMIdentity theID;

        try {
            final AMIdentityRepository amIdRepo = new AMIdentityRepository(token, realm);

            final IdSearchControl idsc = new IdSearchControl();
            idsc.setRecursive(true);
            idsc.setAllReturnAttributes(true);
            // search for the identity
            Set<AMIdentity> results = Collections.emptySet();
            idsc.setMaxResults(0);
            IdSearchResults searchResults =
                    amIdRepo.searchIdentities(IdType.AGENT, uName, idsc);
            if (searchResults != null) {
                results = searchResults.getSearchResults();
            }

            if (results == null || results.size() != 1) {
                throw failureFactory.getException(request, "Client authentication failed");

            }

            theID = results.iterator().next();

            //if the client is deactivated throw InvalidClientException
            if (theID.isActive()){
                return theID;
            } else {
                throw failureFactory.getException(request, "Client authentication failed");
            }
        } catch (SSOException | IdRepoException | LocalizedIllegalArgumentException e) {
            logger.error("ClientVerifierImpl::Unable to get client AMIdentity: ", e);
            throw failureFactory.getException(request, "Client authentication failed");
        }
    }
}
