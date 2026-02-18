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

package jp.co.osstech.openam.core.rest.sms;

import static org.forgerock.json.JsonValue.*;
import static org.forgerock.json.resource.Responses.*;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.IdConstants;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import com.sun.identity.sm.ServiceSchema;
import com.sun.identity.sm.ServiceSchemaManager;
import com.sun.identity.sm.SMSException;
import java.util.ArrayList;
import java.util.Collections;
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
import org.forgerock.openam.core.rest.sms.IdQueryFilterVisitor;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

/**
 * Collection handler for handling queries on the {@literal realm-config/id-repositories} resource.
 */
@RequestHandler
public class IdRepoRealmSmsHandler {

    private final SSOToken adminToken;
    private final Debug debug;
    private final AMResourceBundleCache resourceBundleCache;

    @Inject
    public IdRepoRealmSmsHandler(@Named("frRest") Debug debug, @Named("adminToken") SSOToken adminToken,
            @Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache) {
        this.debug = debug;
        this.adminToken = adminToken;
        this.resourceBundleCache = resourceBundleCache;
    }

    /**
     * Returns the list of configured idrepo instances for the current realm.
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
            String realm = context.asContext(RealmContext.class).getResolvedRealm();

            ServiceSchemaManager schemaMgr = new ServiceSchemaManager(
                    IdConstants.REPO_SERVICE, adminToken);
            ServiceConfigManager svcCfgMgr = new ServiceConfigManager(
                    IdConstants.REPO_SERVICE, adminToken);
            ServiceConfig cfg = svcCfgMgr.getOrganizationConfig(realm, null);
            Set<String> names = (cfg != null) ? cfg.getSubConfigNames() :
                Collections.<String>emptySet();

            List<ResourceResponse> resourceResponses = new ArrayList<>();

            Locale requestLocale = request.getPreferredLocales().getPreferredLocale();

            for (String idrepoName : names) {
                if (searchForId == null || searchForId.equalsIgnoreCase(idrepoName)) {
                    ServiceConfig sc = cfg.getSubConfig(idrepoName);
                    String type = sc.getSchemaID();
                    String typeDescription = getI18NValue(schemaMgr, type, debug, requestLocale);
                    JsonValue result = json(object(
                            field(ResourceResponse.FIELD_CONTENT_ID, idrepoName),
                            field("typeDescription", typeDescription),
                            field("type", type)));

                    resourceResponses.add(newResourceResponse(idrepoName, String.valueOf(result.hashCode()), result));
                }
            }

            return QueryResponsePresentation.perform(handler, request, resourceResponses);

        } catch (SSOException e) {
            debug.warning("IdRepoRealmSmsHandler:: SSOException on create", e);
            return new InternalServerErrorException("Unable to create SMS config.").asPromise();
        } catch (SMSException e) {
            debug.warning("IdRepoRealmSmsHandler:: SMSException on create", e);
            return new InternalServerErrorException("Unable to create SMS config.").asPromise();
        }
    }

    private String getI18NValue(ServiceSchemaManager schemaManager, String type,
            Debug debug, Locale locale) throws SMSException {
        ServiceSchema orgSchema = schemaManager.getOrganizationSchema();
        ServiceSchema subSchema = orgSchema.getSubSchema(type);
        String i18nKey = subSchema.getI18NKey();
        String i18nName = i18nKey;
        ResourceBundle rb = getBundle(schemaManager.getI18NFileName(), locale);
        if (rb != null && i18nKey != null && !i18nKey.isEmpty()) {
            i18nName = com.sun.identity.shared.locale.Locale.getString(rb, i18nKey, debug);
        }
        return i18nName;
    }

    private ResourceBundle getBundle(String name, Locale locale) {
        return resourceBundleCache.getResBundle(name, locale);
    }
}
