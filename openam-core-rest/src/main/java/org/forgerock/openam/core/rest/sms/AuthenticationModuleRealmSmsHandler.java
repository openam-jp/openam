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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2019 Open Source Solution Technology Corporation
 */

package org.forgerock.openam.core.rest.sms;

import static org.forgerock.json.JsonValue.*;
import static org.forgerock.json.resource.Responses.*;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.config.AMAuthenticationInstance;
import com.sun.identity.authentication.config.AMAuthenticationManager;
import com.sun.identity.authentication.config.AMAuthenticationSchema;
import com.sun.identity.authentication.config.AMConfigurationException;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceSchemaManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.annotations.Query;
import org.forgerock.json.resource.annotations.RequestHandler;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

/**
 * Collection handler for handling queries on the {@literal realm-config/authentication/modules} resource.
 *
 * @since 13.0.0
 */
@RequestHandler
public class AuthenticationModuleRealmSmsHandler {

    private final SSOToken adminToken;
    private final Debug debug;
    private final AMResourceBundleCache resourceBundleCache;

    @Inject
    public AuthenticationModuleRealmSmsHandler(@Named("frRest") Debug debug, @Named("adminToken") SSOToken adminToken,
            @Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache) {
        this.debug = debug;
        this.adminToken = adminToken;
        this.resourceBundleCache = resourceBundleCache;
    }

    /**
     * Returns the list of configured authentication module instances for the current realm.
     *
     * {@inheritDoc}
     */
    @Query
    public Promise<QueryResponse, ResourceException> handleQuery(Context context, QueryRequest request,
            QueryResourceHandler handler) {

        String searchForId;
        try {
            searchForId = request.getQueryFilter().accept(new IdQueryFilterVisitor(), null);
        } catch (UnsupportedOperationException e) {
            return new NotSupportedException("Query not supported: " + request.getQueryFilter()).asPromise();
        }
        if (request.getPagedResultsCookie() != null || request.getPagedResultsOffset() > 0 ||
                request.getPageSize() > 0) {
            return new NotSupportedException("Query paging not currently supported").asPromise();
        }

        try {
            SSOToken ssoToken = context.asContext(SSOTokenContext.class).getCallerSSOToken();
            String realm = context.asContext(RealmContext.class).getResolvedRealm();
            AMAuthenticationManager mgr = new AMAuthenticationManager(ssoToken, realm);
            Set<AMAuthenticationInstance> moduleInstances = mgr.getAuthenticationInstances();

            List<ResourceResponse> resourceResponses = new ArrayList<>();
            
            Locale requestLocale = request.getPreferredLocales().getPreferredLocale();

            for (AMAuthenticationInstance instance : moduleInstances) {
                String name = instance.getName();
                if (searchForId == null || searchForId.equalsIgnoreCase(name)) {
                    try {
                        ServiceSchemaManager schemaManager = getSchemaManager(instance.getType());
                        String type = schemaManager.getResourceName();
                        String typeDescription = getI18NValue(schemaManager, instance.getType(), debug, requestLocale);
                        JsonValue result = json(object(
                                field(ResourceResponse.FIELD_CONTENT_ID, name),
                                field("typeDescription", typeDescription),
                                field("type", type)));

                        resourceResponses.add(newResourceResponse(name, String.valueOf(result.hashCode()), result));
                    } catch (AMConfigurationException ex) {
                        debug.error("AuthenticationModuleCollectionHandler.handleQuery(): Invalid auth module " +
                                "instance configuration: {}", name);
                        if (debug.messageEnabled()) {
                            debug.message(
                                    "AuthenticationModuleCollectionHandler.handleQuery(): Configuration exception: {}",
                                    name, ex);
                        }
                    }
                }
            }

            return QueryResponsePresentation.perform(handler, request, resourceResponses);

        } catch (AMConfigurationException e) {
            debug.warning("::AuthenticationModuleCollectionHandler:: Querying configured auth modules failed", e);
            return new InternalServerErrorException("Unable to create SMS config: " + e.getMessage()).asPromise();
        } catch (SSOException e) {
            debug.warning("::AuthenticationModuleCollectionHandler:: SSOException on create", e);
            return new InternalServerErrorException("Unable to create SMS config: " + e.getMessage()).asPromise();
        } catch (SMSException e) {
            debug.warning("::AuthenticationModuleCollectionHandler:: SMSException on create", e);
            return new InternalServerErrorException("Unable to create SMS config.").asPromise();
        }
    }

    private ServiceSchemaManager getSchemaManager(String authType) throws SSOException, SMSException,
            AMConfigurationException {
        AMAuthenticationManager authenticationManager = new AMAuthenticationManager(adminToken, "/");
        AMAuthenticationSchema schema = authenticationManager.getAuthenticationSchema(authType);
        return new ServiceSchemaManager(schema.getServiceName(), adminToken);
    }

    protected String getI18NValue(ServiceSchemaManager schemaManager, String authType,
            Debug debug, Locale locale) {
        String i18nKey = schemaManager.getI18NKey();
        String i18nName = authType;
        ResourceBundle rb = getBundle(schemaManager.getI18NFileName(), locale);
        if (rb != null && i18nKey != null && !i18nKey.isEmpty()) {
            i18nName = com.sun.identity.shared.locale.Locale.getString(rb, i18nKey, debug);
        }
        return i18nName;
    }

    protected ResourceBundle getBundle(String name, Locale locale) {
        return resourceBundleCache.getResBundle(name, locale);
    }

}
