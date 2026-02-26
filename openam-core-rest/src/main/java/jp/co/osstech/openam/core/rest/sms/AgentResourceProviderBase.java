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

import static org.forgerock.openam.utils.Time.currentTimeMillis;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.openam.core.rest.sms.SmsJsonConverter;
import org.forgerock.openam.core.rest.sms.SmsResourceProvider;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.ExceptionHandler;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.PromiseImpl;
import org.forgerock.util.promise.ResultHandler;

import com.iplanet.sso.SSOException;
import com.sun.identity.common.configuration.AgentConfiguration;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdConstants;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;

/**
 * REST resource base for Agent & Agent Group Management.
 */
public abstract class AgentResourceProviderBase extends SmsResourceProvider {

    public static final String AM_SERVER_PORT = "com.iplanet.am.server.port";

    private static final long MAX_AWAIT_TIMEOUT = 5000L;
    private static final String I18N_FILE = "schemaI18n";

    protected AgentResourceProviderBase(ServiceSchema schema, SchemaType type, List<ServiceSchema> subSchemaPath,
            String uriPath, boolean serviceHasInstanceName, SmsJsonConverter converter, Debug debug,
            AMResourceBundleCache resourceBundleCache, Locale defaultLocale) {
        super(schema, type, subSchemaPath, uriPath, serviceHasInstanceName, converter, debug, resourceBundleCache,
                defaultLocale);
    }

    public abstract Promise<ResourceResponse, ResourceException> readInstance(
            Context context, String resourceId);

    protected Map<String, Set<String>> getAgentAttributes(AMIdentity amid)
            throws SSOException, IdRepoException {
        Map attrs = amid.getAttributes();

        // Remove AgentType not defined in the schema
        attrs.remove(IdConstants.AGENT_TYPE);

        // Adjust attribute values
        AgentConfiguration.removeAgentRootURLKey(schema.getName(), attrs);

        return attrs;
    }

    protected String getI18NName(Locale locale) {
        String agentType = schema.getName();
        String i18nName = agentType;
        ResourceBundle schemaI18n = ResourceBundle.getBundle(I18N_FILE, locale);
        i18nName = schemaI18n.getString("agents." + agentType + ".name");
        return i18nName;
    }

    protected Promise<Void, ResourceException> awaitCreation(Context context, String resourceId) {
        final PromiseImpl<Void, ResourceException> awaitPromise = PromiseImpl.create();
        await(context, resourceId, awaitPromise, currentTimeMillis(), awaitCreationResultHandler(awaitPromise),
                awaitCreationExceptionHandler(context, resourceId, awaitPromise, currentTimeMillis()));
        return awaitPromise;
    }

    protected Promise<Void, ResourceException> awaitDeletion(Context context, String resourceId) {
        final PromiseImpl<Void, ResourceException> awaitPromise = PromiseImpl.create();
        await(context, resourceId, awaitPromise, currentTimeMillis(),
                awaitDeletionResultHandler(context, resourceId, awaitPromise, currentTimeMillis()),
                awaitDeletionExceptionHandler(context, resourceId, awaitPromise, currentTimeMillis()));
        return awaitPromise;
    }

    protected void await(Context context, String resourceId, PromiseImpl<Void, ResourceException> awaitPromise,
            long startTime, ResultHandler<ResourceResponse> resultHandler,
            ExceptionHandler<ResourceException> exceptionHandler) {
        if (currentTimeMillis() - startTime > MAX_AWAIT_TIMEOUT) {
            awaitPromise.handleResult(null);
            return;
        }
        try {
            Thread.sleep(100L);
        } catch (InterruptedException e) {
            debug.error("Thread interrupted while awaiting agent resource creation/deletion", e);
            awaitPromise.handleException(new InternalServerErrorException());
        }
        readInstance(context, resourceId)
                .thenOnResult(resultHandler)
                .thenOnException(exceptionHandler);
    }

    protected ResultHandler<ResourceResponse> awaitCreationResultHandler(
            final PromiseImpl<Void, ResourceException> awaitPromise) {
        return new ResultHandler<ResourceResponse>() {
            @Override
            public void handleResult(ResourceResponse result) {
                awaitPromise.handleResult(null);
            }
        };
    }

    protected ExceptionHandler<ResourceException> awaitCreationExceptionHandler(final Context context,
            final String resourceId, final PromiseImpl<Void, ResourceException> awaitPromise, final long startTime) {
        return new ExceptionHandler<ResourceException>() {
            @Override
            public void handleException(ResourceException exception) {
                if (ResourceException.NOT_FOUND != exception.getCode()) {
                    debug.warning("Unexpected exception returned while awaiting agent resource creation", exception);
                }
                await(context, resourceId, awaitPromise, startTime,
                        awaitCreationResultHandler(awaitPromise),
                        awaitCreationExceptionHandler(context, resourceId, awaitPromise, startTime));
            }
        };
    }

    protected ResultHandler<ResourceResponse> awaitDeletionResultHandler(final Context context, final String resourceId,
            final PromiseImpl<Void, ResourceException> awaitPromise, final long startTime) {
        return new ResultHandler<ResourceResponse>() {
            @Override
            public void handleResult(ResourceResponse result) {
                await(context, resourceId, awaitPromise, startTime,
                        awaitDeletionResultHandler(context, resourceId, awaitPromise, startTime),
                        awaitDeletionExceptionHandler(context, resourceId, awaitPromise, startTime));
            }
        };
    }

    protected ExceptionHandler<ResourceException> awaitDeletionExceptionHandler(final Context context,
            final String resourceId, final PromiseImpl<Void, ResourceException> awaitPromise, final long startTime) {
        return new ExceptionHandler<ResourceException>() {
            @Override
            public void handleException(ResourceException exception) {
                if (ResourceException.NOT_FOUND != exception.getCode()) {
                    debug.warning("Unexpected exception returned while awaiting agent resource deletion", exception);
                    await(context, resourceId, awaitPromise, startTime,
                            awaitDeletionResultHandler(context, resourceId, awaitPromise, startTime),
                            awaitDeletionExceptionHandler(context, resourceId, awaitPromise, startTime));
                } else {
                    awaitPromise.handleResult(null);
                }
            }
        };
    }

    protected boolean isEmptyAttribute(Set<String> attrSet) {
        if (CollectionUtils.isEmpty(attrSet)) {
            return true;
        }
        for (String attr : attrSet) {
            if (attr != null && !attr.isEmpty()) {
                return false;
            }
        }
        return true;
    }
}
