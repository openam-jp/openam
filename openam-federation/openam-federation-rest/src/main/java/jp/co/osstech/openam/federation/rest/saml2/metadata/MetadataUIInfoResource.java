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
package jp.co.osstech.openam.federation.rest.saml2.metadata;

import java.util.HashMap;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.Responses;
import org.forgerock.json.resource.annotations.Read;
import org.forgerock.json.resource.annotations.RequestHandler;
import org.forgerock.json.resource.http.HttpContext;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

import com.sun.identity.common.ISLocaleContext;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.shared.debug.Debug;

import jp.co.osstech.openam.saml2.metadata.LogoInfo;
import jp.co.osstech.openam.saml2.metadata.UIInfoCollector;

/**
 * Resource class for UI informations of SAML2 service providers.
 */
@RequestHandler
public class MetadataUIInfoResource {

    private static final String ENTITY_ID = "entityID";
    private static final Debug DEBUG = Debug.getInstance(MetadataUIInfoResource.class.getSimpleName());

    @Read
    public Promise<ResourceResponse, ResourceException> read(Context context, ReadRequest request) {
        String realm = getRealm(context);
        String entityID = getEntityId(request);
        String lang = getLang(context);
        UIInfoCollector collector = new UIInfoCollector(realm, entityID);
        try {
            if (collector.spExists()) {
                JsonValue response = collectUIInfo(collector, lang);
                return Promises.newResultPromise(
                        Responses.newResourceResponse(entityID, String.valueOf(response.hashCode()), response));
            } else {
                return new NotFoundException().asPromise();
            }
        } catch (SAML2MetaException e) {
            DEBUG.error("An error occured while retrieving UI Info.", e);
            return new InternalServerErrorException("Can't retrieve UI Info").asPromise();
        }
    }

    private String getRealm(Context context) {
        return context.asContext(RealmContext.class).getBaseRealm();
    }

    private String getEntityId(ReadRequest request) {
        return request.getAdditionalParameter(ENTITY_ID);
    }

    private String getLang(Context context) {
        ISLocaleContext localeContext = new ISLocaleContext();
        HttpContext httpContext = context.asContext(HttpContext.class);
        localeContext.setLocale(httpContext);
        return localeContext.getLocale().getLanguage();
    }

    private JsonValue collectUIInfo(UIInfoCollector collector, String lang) throws SAML2MetaException {
        JsonValue response = new JsonValue(new HashMap<>());

        LogoInfo logoInfo = collector.getLogoInfo(lang);
        if (logoInfo != null) {
            response.add("spLogoURL", logoInfo.getUrl());
            response.add("spLogoHeight", String.valueOf(logoInfo.getHeight()));
            response.add("spLogoWidth", String.valueOf(logoInfo.getWidth()));
        }

        response.add("spDisplayName", collector.getDisplayName(lang));
        response.add("spDescription", collector.getDescription(lang));
        response.add("spInformationURL", collector.getInformationURL(lang));
        response.add("spPrivacyStatementURL", collector.getPrivacyStatementURL(lang));
        response.add("spOrganizationDisplayName", collector.getOrganizationDisplayName(lang));
        return response;
    }

}
