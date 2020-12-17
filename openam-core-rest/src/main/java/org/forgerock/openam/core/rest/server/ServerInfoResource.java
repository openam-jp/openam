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
 * Copyright 2013-2016 ForgeRock AS.
 * Portions copyright 2019-2020 Open Source Solution Technology Corporation
 */
package org.forgerock.openam.core.rest.server;

import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.core.rest.server.SelfServiceInfo.SelfServiceInfoBuilder;
import static org.forgerock.util.promise.Promises.newResultPromise;

import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.client.AuthClientUtils;
import com.sun.identity.authentication.service.AuthUtils;
import com.sun.identity.common.ISLocaleContext;
import com.sun.identity.common.configuration.MapValueParser;
import com.sun.identity.common.CaseInsensitiveHashMap;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.encode.CookieUtils;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

import jp.co.osstech.openam.shared.cookie.SameSite;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.DeleteRequest;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.json.resource.http.HttpContext;
import static org.forgerock.json.resource.Responses.newActionResponse;
import org.forgerock.openam.rest.RealmAwareResource;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.rest.ServiceConfigUtils;
import org.forgerock.openam.services.RestSecurity;
import org.forgerock.openam.services.RestSecurityProvider;
import org.forgerock.openam.sm.config.ConsoleConfigHandler;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import java.security.AccessController;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.forgerock.openam.shared.security.whitelist.RedirectUrlValidator;

/**
 * Represents Server Information that can be queried via a REST interface.
 * <p>
 * This resources acts as a read only resource for the moment.
 */
public class ServerInfoResource extends RealmAwareResource {

    private final Debug debug;
    private final Map<String, ServiceConfig> realmSocialAuthServiceConfigMap = new ConcurrentHashMap<>();
    private final ConsoleConfigHandler configHandler;
    private final RestSecurityProvider restSecurityProvider;
    private final RedirectUrlValidator<String> urlValidator;

    private final static String COOKIE_DOMAINS = "cookieDomains";
    private final static String ALL_SERVER_INFO = "*";
    public static final String VALIDATE_GOTO_ACTION_ID = "validateGoto";
    private final Map<String, ActionHandler> actionHandlers;
    private final static String[] xuiCookies = {CookieUtils.getAmCookieName(), "authId"};

    @Inject
    public ServerInfoResource(@Named("frRest") Debug debug, ConsoleConfigHandler configHandler, 
            RestSecurityProvider restSecurityProvider, @Named("CoreRest") RedirectUrlValidator<String> urlValidator) {
        this.debug = debug;
        this.configHandler = configHandler;
        this.restSecurityProvider = restSecurityProvider;
        this.urlValidator = urlValidator;
        
        actionHandlers = new CaseInsensitiveHashMap<>();
        actionHandlers.put(VALIDATE_GOTO_ACTION_ID, new ValidateGotoActionHandler());
    }

    private final MapValueParser nameValueParser = new MapValueParser();

    /**
     * Retrieves the cookie domains set on the server.
     */
    private Promise<ResourceResponse, ResourceException> getCookieDomains() {
        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>(1));
        Set<String> cookieDomains;
        ResourceResponse resource;
        int rev;
        try {
            cookieDomains = AuthClientUtils.getCookieDomains();
            rev = cookieDomains.hashCode();
            result.put("domains", cookieDomains);
            resource = newResourceResponse(COOKIE_DOMAINS, Integer.toString(rev), result);
            if (debug.messageEnabled()) {
                debug.message("ServerInfoResource.getCookieDomains ::" +
                        " Added resource to response: " + COOKIE_DOMAINS);
            }
            return newResultPromise(resource);
        } catch (Exception e) {
            debug.error("ServerInfoResource.getCookieDomains : Cannot retrieve cookie domains.", e);
            return new NotFoundException(e.getMessage()).asPromise();
        }
    }

    /**
     * Retrieves all server info set on the server.
     *
     * @param context
     *         Current Server Context.
     * @param realm
     *         realm in whose security context we use.
     */
    private Promise<ResourceResponse, ResourceException> getAllServerInfo(Context context, String realm) {
        JsonValue result = new JsonValue(new LinkedHashMap<String, Object>(1));
        Set<String> cookieDomains;
        ResourceResponse resource;

        //added for the XUI to be able to understand its locale to request the appropriate translations to cache
        ISLocaleContext localeContext = new ISLocaleContext();
        HttpContext httpContext = context.asContext(HttpContext.class);
        localeContext.setLocale(httpContext); //we have nothing else to go on at this point other than their request

        SelfServiceInfo selfServiceInfo = configHandler.getConfig(realm, SelfServiceInfoBuilder.class);
        RestSecurity restSecurity = restSecurityProvider.get(realm);
        Set<String> protectedUserAttributes = new HashSet<>();
        protectedUserAttributes.addAll(selfServiceInfo.getProtectedUserAttributes());
        protectedUserAttributes.addAll(restSecurity.getProtectedUserAttributes());

        try {
            cookieDomains = AuthClientUtils.getCookieDomains();
            result.put("domains", cookieDomains);
            result.put("protectedUserAttributes", protectedUserAttributes);
            result.put("cookieName", SystemProperties.get(Constants.AM_COOKIE_NAME, "iPlanetDirectoryPro"));
            result.put("secureCookie", CookieUtils.isCookieSecure());
            result.put("forgotPassword", String.valueOf(selfServiceInfo.isForgottenPasswordEnabled()));
            result.put("forgotUsername", String.valueOf(selfServiceInfo.isForgottenUsernameEnabled()));
            result.put("kbaEnabled", String.valueOf(selfServiceInfo.isKbaEnabled()));
            result.put("selfRegistration", String.valueOf(selfServiceInfo.isUserRegistrationEnabled()));
            result.put("lang", getJsLocale(localeContext.getLocale()));
            result.put("successfulUserRegistrationDestination", selfServiceInfo.getUserRegistrationDestination());
            result.put("socialImplementations", getSocialAuthnImplementations(realm));
            result.put("referralsEnabled", Boolean.FALSE.toString());
            result.put("zeroPageLogin", AuthUtils.getZeroPageLoginConfig(realm));
            result.put("realm", realm);
            result.put("xuiUserSessionValidationEnabled", SystemProperties.getAsBoolean(Constants.XUI_USER_SESSION_VALIDATION_ENABLED, true));


            AttributesContext requestContext = context.asContext(AttributesContext.class);
            Map<String, Object> requestAttributes = requestContext.getAttributes();
            final HttpServletRequest httpServletRequest = (HttpServletRequest) requestAttributes.get(HttpServletRequest.class.getName());
            Map<String, String> cookieSameSiteMap = getSameSiteMap(httpServletRequest);
            if (CollectionUtils.isNotEmpty(cookieSameSiteMap)) {
                result.put("cookieSamesiteMap", cookieSameSiteMap);
            }
            
            if (debug.messageEnabled()) {
                debug.message("ServerInfoResource.getAllServerInfo ::" +
                        " Added resource to response: " + ALL_SERVER_INFO);
            }

            resource = newResourceResponse(ALL_SERVER_INFO, Integer.toString(result.asMap().hashCode()), result);

            return newResultPromise(resource);
        } catch (Exception e) {
            debug.error("ServerInfoResource.getAllServerInfo : Cannot retrieve all server info domains.", e);
            return new NotFoundException(e.getMessage()).asPromise();
        }
    }

    /**
     * Get SameSite map for XUI.
     *
     * @param request The HttpServletRequest object.
     * @return SameSite map.
     */
    private Map<String, String> getSameSiteMap(HttpServletRequest request) {
        Map<String, String> map = new HashMap<String, String>();
        if (!SameSite.isSupportedClient(request)) {
            return map;
        }
        for (String cookieName : xuiCookies) {
            SameSite samesite = CookieUtils.getSameSite(cookieName);
            if (samesite != null) {
                map.put(cookieName, samesite.getValue());
            }
        }
        return map;
    }

    private String getJsLocale(Locale locale) {
        String jsLocale = locale.getLanguage();
        if (StringUtils.isNotEmpty(locale.getCountry())) {
            jsLocale += "-" + locale.getCountry();
        }
        return jsLocale;
    }

    /**
     * Read out the data whose schema is defined in the file socialAuthN.xml. The enabled implementations value gives
     * us the social authentication implementations we care about.  We use the values there to index into the display
     * names, auth chains and icons.
     *
     * @param realm
     *         The realm/organization name
     */
    private List<SocialAuthenticationImplementation> getSocialAuthnImplementations(String realm) {

        List<SocialAuthenticationImplementation> implementations = new ArrayList<>();

        try {
            final ServiceConfig serviceConfig = getSocialAuthenticationServiceConfig(realm);
            Set<String> enabledImplementationSet = ServiceConfigUtils.getSetAttribute(serviceConfig,
                    SocialAuthenticationImplementation.ENABLED_IMPLEMENTATIONS_ATTRIBUTE);

            if (enabledImplementationSet != null) {
                for (String name : enabledImplementationSet) {

                    SocialAuthenticationImplementation implementation = new SocialAuthenticationImplementation();
                    implementation.setDisplayName(getEntryForImplementation(serviceConfig, name,
                            SocialAuthenticationImplementation.DISPLAY_NAME_ATTRIBUTE));
                    implementation.setAuthnChain(getEntryForImplementation(serviceConfig, name,
                            SocialAuthenticationImplementation.CHAINS_ATTRIBUTE));
                    implementation.setIconPath(getEntryForImplementation(serviceConfig, name,
                            SocialAuthenticationImplementation.ICONS_ATTRIBUTE));

                    if (implementation.isValid()) {
                        implementations.add(implementation);
                    }
                }

            }
        } catch (SSOException sso) {
            debug.error("Caught SSO Exception while trying to get the ServiceConfigManager", sso);
        } catch (SMSException sms) {
            debug.error("Caught SMS Exception while trying to get the ServiceConfigManager", sms);
        } catch (Exception e) {
            if (debug.errorEnabled()) {
                debug.error("Caught exception while trying to get the attribute " +
                        SocialAuthenticationImplementation.ENABLED_IMPLEMENTATIONS_ATTRIBUTE, e);
            }
        }

        return implementations;

    }

    private ServiceConfig getSocialAuthenticationServiceConfig(final String realm) throws SSOException, SMSException {

        ServiceConfig realmSocialAuthServiceConfig = realmSocialAuthServiceConfigMap.get(realm);
        if (realmSocialAuthServiceConfig == null || !realmSocialAuthServiceConfig.isValid()) {
            synchronized (realmSocialAuthServiceConfigMap) {
                realmSocialAuthServiceConfig = realmSocialAuthServiceConfigMap.get(realm);
                if (realmSocialAuthServiceConfig == null || !realmSocialAuthServiceConfig.isValid()) {
                    SSOToken token = AccessController.doPrivileged(AdminTokenAction.getInstance());
                    ServiceConfigManager mgr =
                            new ServiceConfigManager(SocialAuthenticationImplementation.SERVICE_NAME, token);
                    realmSocialAuthServiceConfig = mgr.getOrganizationConfig(realm, null);
                    realmSocialAuthServiceConfigMap.put(realm, realmSocialAuthServiceConfig);
                }
            }
        }

        return realmSocialAuthServiceConfig;
    }

    /**
     * Given the specified name, use the serviceConfig object to retrieve the entire set of [name]=value pairs
     * specified.
     *
     * @param serviceConfig
     *         The service config
     * @param name
     *         The implementation name we're looking for, e.g. google
     * @param attributeName
     *         The attribute we're interested in
     *
     * @return The value (as in [name]=value) corresponding to the specified name, or null if not found.
     */
    private String getEntryForImplementation(ServiceConfig serviceConfig, String name, String attributeName) {
        return nameValueParser.getValueForName(name, ServiceConfigUtils.getSetAttribute(serviceConfig, attributeName));
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<ActionResponse, ResourceException> actionCollection(Context context, ActionRequest request) {

        return internalHandleAction(context, request);
    }

    private Promise<ActionResponse, ResourceException> internalHandleAction(Context context, ActionRequest request) {

        final String action = request.getAction();
        final ActionHandler actionHandler = actionHandlers.get(action);

        if (actionHandler != null) {
            return actionHandler.handle(context, request);

        } else {
            String message = String.format("Action %s not implemented for this resource", action);
            NotSupportedException e = new NotSupportedException(message);
            return e.asPromise();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<ActionResponse, ResourceException> actionInstance(Context context, String s,
            ActionRequest request) {
        return RestUtils.generateUnsupportedOperation();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<ResourceResponse, ResourceException> createInstance(Context context, CreateRequest request) {
        return RestUtils.generateUnsupportedOperation();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context, String s,
            DeleteRequest request) {
        return RestUtils.generateUnsupportedOperation();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context context, String s,
            PatchRequest request) {
        return RestUtils.generateUnsupportedOperation();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {
        return RestUtils.generateUnsupportedOperation();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, String resourceId,
            ReadRequest request) {

        final String realm = getRealm(context);

        debug.message("ServerInfoResource :: READ : in realm: " + realm);

        if (COOKIE_DOMAINS.equalsIgnoreCase(resourceId)) {
            return getCookieDomains();
        } else if (ALL_SERVER_INFO.equalsIgnoreCase(resourceId)) {
            return getAllServerInfo(context, realm);
        } else { // for now this is the only case coming in, so fail if otherwise
            final ResourceException e = new NotSupportedException("ResourceId not supported: " + resourceId);
            if (debug.errorEnabled()) {
                debug.error("ServerInfoResource :: READ : in realm: " + realm +
                        ": Cannot receive information on requested resource: " + resourceId, e);
            }
            return e.asPromise();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, String s,
            UpdateRequest request) {
        return RestUtils.generateUnsupportedOperation();
    }
    
    /**
     * Defines a delegate capable of handling a particular action for a collection or instance
     */
    private interface ActionHandler {
        Promise<ActionResponse, ResourceException> handle(Context context, ActionRequest request);
    }
    
    /**
     * Validates the current goto against the list of allowed gotos, and returns
     * either the allowed goto as sent in, or null.
     *
     * @param context Current Server Context
     * @param request Request from client to confirm registration
     */
    private class ValidateGotoActionHandler implements ActionHandler {

        @Override
        public Promise<ActionResponse, ResourceException> handle(final Context context, final ActionRequest request) {

            final JsonValue jVal = request.getContent();
            JsonValue result = new JsonValue(new LinkedHashMap<>(1));

            String gotoURL = urlValidator.getRedirectUrl(getRealm(context),
                    urlValidator.getValueFromJson(jVal, RedirectUrlValidator.GOTO),
                    null);
            result.put("validatedUrl", gotoURL);
            return newResultPromise(newActionResponse(result));
        }
    }
}
