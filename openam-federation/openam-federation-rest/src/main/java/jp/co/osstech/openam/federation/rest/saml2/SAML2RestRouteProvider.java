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
 * Copyright 2026 OSSTech Corporation
 */
package jp.co.osstech.openam.federation.rest.saml2;

import org.forgerock.openam.rest.AbstractRestRouteProvider;
import org.forgerock.openam.rest.ResourceRouter;
import org.forgerock.openam.rest.Routers;
import org.forgerock.openam.rest.authz.AdminOnlyAuthzModule;

import jp.co.osstech.openam.federation.rest.saml2.consent.AttributeConsentResource;
import jp.co.osstech.openam.federation.rest.saml2.metadata.MetadataUIInfoResource;

/**
 * The class <code>SAML2RestRouteProvider</code> add route for SAML2
 * resources.
 */
public class SAML2RestRouteProvider extends AbstractRestRouteProvider {

    @Override
    public void addResourceRoutes(ResourceRouter rootRouter, ResourceRouter realmRouter) {
        realmRouter.route("saml2/consent/{consentID}")
                .authenticateWith(Routers.ssoToken())
                .toAnnotatedSingleton(AttributeConsentResource.class);

        realmRouter.route("saml2/metadata/uiinfo")
                .authenticateWith(Routers.none())
                .toAnnotatedSingleton(MetadataUIInfoResource.class);
    }
}
