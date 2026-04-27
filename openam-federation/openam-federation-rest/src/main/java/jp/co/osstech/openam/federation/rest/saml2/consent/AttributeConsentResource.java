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
package jp.co.osstech.openam.federation.rest.saml2.consent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import javax.inject.Inject;
import javax.inject.Named;

import org.forgerock.http.routing.UriRouterContext;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.Responses;
import org.forgerock.json.resource.annotations.Action;
import org.forgerock.json.resource.annotations.RequestHandler;
import org.forgerock.json.resource.http.HttpContext;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.common.ISLocaleContext;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.profile.CacheObject;
import com.sun.identity.saml2.profile.IDPCache;
import com.sun.identity.saml2.profile.ServerFaultException;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.SMSException;

import jp.co.osstech.openam.saml2.consent.AttributeConsentActorFactory;
import jp.co.osstech.openam.saml2.consent.AttributeConsentCache;
import jp.co.osstech.openam.saml2.consent.AttributeConsentStep;
import jp.co.osstech.openam.saml2.consent.ConsentRequiredAttribute;
import jp.co.osstech.openam.saml2.consent.AttributeConsent.ConsentType;

/**
 * The class <code>AttributeConsentResource</code> is responsible for handling
 * REST requests and processing SAML2 attribute consent steps.
 */
@RequestHandler
public class AttributeConsentResource {

    private static final String CONSENT_ID = "consentID";

    private static final String ATTRIBUTE_NAME = "attributeName";
    private static final String DISPLAY_NAME = "displayName";
    private static final String ATTRIBUTE_VALUE = "attributeValue";
    private static final String HISTORY = "history";
    private static final String ATTRIBUTES = "attributes";
    private static final String TYPE = "type";

    private Debug debug;
    private AttributeConsentActorFactory factory;

    @Inject
    public AttributeConsentResource(@Named("frRest") Debug debug, AttributeConsentActorFactory factory) {
        this.debug = debug;
        this.factory = factory;
    }

    @Action
    public Promise<ActionResponse, ResourceException> getAttributes(
            Context context, ActionRequest request) {
        try {

            SSOToken ssoToken = getSSOToken(context);
            Locale locale = getLocale(context);
            String consentID = getConsentID(context);
            String encryptedHistory = getHistory(request);
            AttributeConsentStep consentStep = getConsentStep(context, request);
            boolean forceConsent = forceConsent(request);

            JsonValue response;
            if (!consentStep.requireConsent(ssoToken, consentID, encryptedHistory) && !forceConsent) {
                response = new JsonValue(Collections.EMPTY_LIST);
            } else {
                List<ConsentRequiredAttribute> attributes = consentStep.getConsentRequiredAttributes(ssoToken, locale);
                response = convertToJsonValue(attributes);
            }
            return Promises.newResultPromise(Responses.newActionResponse(response));

        } catch (SAML2Exception | SSOException | IdRepoException e) {
            debug.error("Unable to perform valid consent step.", e);
            return new InternalServerErrorException().asPromise();
        } catch (BadRequestException | InternalServerErrorException e) {
            return e.asPromise();
        }
    }

    @Action
    public Promise<ActionResponse, ResourceException> agree(
            Context context, ActionRequest request) {
        try {
            SSOToken ssoToken = getSSOToken(context);
            String encryptedHistory = getHistory(request);
            List<String> agreedAttributes = getAgreedAttributes(request);
            String consentID = getConsentID(context);
            AttributeConsentStep consentStep = getConsentStep(context, request);

            AttributeConsentCache consentCache = consentStep.getValidConsentCache(ssoToken, consentID);
            if (consentCache == null) {
                throw new BadRequestException("Invalid consent ID");
            }

            if (agreedAttributes != null && agreedAttributes.isEmpty()) {
                // If empty, It doesn't need to update history or audit.
                consentCache.agree();

                JsonValue response = new JsonValue(new HashMap<>());
                response.add(HISTORY, encryptedHistory);
                return Promises.newResultPromise(Responses.newActionResponse(response));
            }
            ConsentType consentType = getConsentType(request);
            String newHistory = consentStep.agree(ssoToken, encryptedHistory, agreedAttributes, consentType, consentID);

            JsonValue response = new JsonValue(new HashMap<>());
            response.add(HISTORY, newHistory);
            return Promises.newResultPromise(Responses.newActionResponse(response));

        } catch (BadRequestException | InternalServerErrorException e) {
            return e.asPromise();
        } catch (JsonProcessingException | SSOException | IdRepoException | SAML2Exception e) {
            return new InternalServerErrorException().asPromise();
        }
    }

    @Action
    public Promise<ActionResponse, ResourceException> reject(
            Context context, ActionRequest request) {
        try {
            SSOToken ssoToken = getSSOToken(context);
            List<String> attributes = getAgreedAttributes(request);
            String encryptedHistory = getHistory(request);
            AttributeConsentStep consentStep = getConsentStep(context, request);

            consentStep.reject(ssoToken, attributes);
            JsonValue response = new JsonValue(new HashMap<>());
            response.add(HISTORY, encryptedHistory);
            return Promises.newResultPromise(Responses.newActionResponse(response));

        } catch (BadRequestException | InternalServerErrorException e) {
            return e.asPromise();
        }
    }

    private JsonValue getRequestParamOrThrow(ActionRequest request, String paramName)
            throws BadRequestException {
        JsonValue reqestParams = request.getContent();
        if (reqestParams.keys().contains(paramName)) {
            return reqestParams.get(paramName);
        } else {
            throw new BadRequestException(paramName + " is required.");
        }
    }

    private AttributeConsentCache getConsentCache(Context context) throws BadRequestException, SSOException {
        String consentID = getConsentID(context);
        CacheObject cache = (CacheObject) IDPCache.attributeConsentCache.get(consentID);
        if (cache == null) {
            throw new BadRequestException("Invalid consent ID");
        }
        AttributeConsentCache consentCache = (AttributeConsentCache) cache.getObject();
        SSOToken ssoToken = getSSOToken(context);
        if (!consentCache.getUserDN().equals(ssoToken.getPrincipal().getName())) {
            throw new BadRequestException("Invalid consent ID");
        }
        return consentCache;
    }

    private String getHistory(ActionRequest request) {
        return request.getContent().get(HISTORY).asString();
    }

    private List<String> getAgreedAttributes(ActionRequest request) throws BadRequestException {
        return getRequestParamOrThrow(request, ATTRIBUTES).asList(String.class);
    }

    private ConsentType getConsentType(ActionRequest request) throws BadRequestException {
        String consentTypeStr = getRequestParamOrThrow(request, TYPE).asString();
        try {
            return ConsentType.valueOf(consentTypeStr);
        } catch (IllegalArgumentException e) {
            debug.error("Invalid consent type {} is specified.", consentTypeStr);
            throw new BadRequestException("Invalid consent type.");
        }
    }

    private String getConsentID(Context context) throws BadRequestException {
        String consentID = context.asContext(UriRouterContext.class)
                .getUriTemplateVariables()
                .get(CONSENT_ID);
        if (consentID == null) {
            throw new BadRequestException(CONSENT_ID + " is required.");
        }
        try {
            UUID.fromString(consentID);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid consentID.");
        }
        return consentID;
    }

    private Locale getLocale(Context context) {
        ISLocaleContext locale = new ISLocaleContext();
        HttpContext httpContext = context.asContext(HttpContext.class);
        locale.setLocale(httpContext);
        return locale.getLocale();
    }

    private SSOToken getSSOToken(Context context) {
        return context.asContext(SSOTokenContext.class).getCallerSSOToken();
    }

    private boolean forceConsent(ActionRequest request) {
        JsonValue requestParams = request.getContent();
        return Boolean.parseBoolean(
                requestParams.get(AttributeConsentStep.REQUEST_PARAM_FORCE_CONSENT).asString());
    }

    private AttributeConsentStep getConsentStep(Context context, ActionRequest request)
            throws BadRequestException, InternalServerErrorException {
        try {
            AttributeConsentCache cache = getConsentCache(context);
            String realm = cache.getRealm();
            String idpEntityId = cache.getIdpEntityId();
            String spEntityId = cache.getSpEntityId();
            return factory.getConsentStep(realm, idpEntityId, spEntityId);
        } catch (SAML2Exception | SSOException | ServerFaultException | SMSException e) {
            debug.error("Unable to perform valid consent step.", e);
            throw new InternalServerErrorException();
        }
    }

    private JsonValue convertToJsonValue(List<ConsentRequiredAttribute> attributes) {
        JsonValue response = new JsonValue(new ArrayList<>());
        for (ConsentRequiredAttribute attribute : attributes) {
            JsonValue info = new JsonValue(new HashMap<>());
            info.put(ATTRIBUTE_NAME, attribute.attributeName());
            info.put(DISPLAY_NAME, attribute.displayName());
            info.put(ATTRIBUTE_VALUE, attribute.attributeValue());
            response.add(info.getObject());
        }
        return response;
    }
}
