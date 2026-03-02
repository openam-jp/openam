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
package jp.co.osstech.openam.core.rest.session;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.rest.RestUtils.realmFor;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.annotations.Action;
import org.forgerock.json.resource.annotations.Query;
import org.forgerock.json.resource.annotations.RequestHandler;
import org.forgerock.openam.core.rest.session.query.SessionQueryManager;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.openam.session.SessionCache;
import org.forgerock.openam.session.SessionConstants;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.query.QueryFilter;

import com.iplanet.dpro.session.Session;
import com.iplanet.dpro.session.SessionException;
import com.iplanet.dpro.session.SessionID;
import com.iplanet.dpro.session.share.SessionInfo;
import com.iplanet.services.naming.WebtopNaming;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.sm.SMSException;

/**
 * REST resource for Session Management.
 */
@RequestHandler
public class SessionResource {

    private static final String FIELD_USER_NAME = "username";
    private static final String FIELD_SESSION_HANDLE = "sessionHandle";
    private static final String FIELD_REALM = "realm";
    private static final String FIELD_MAX_SESSION_EXPIRATION_TIME = "maxSessionExpirationTime";
    private static final String FIELD_MAX_SESSION_TIME = "maxSessionTime";
    private static final String FIELD_IDLE_SESSION_EXPIRATION_TIME = "idleSessionExpirationTime";
    private static final String FIELD_MAX_IDLE_TIME = "maxIdleTime";

    private SessionQueryManager queryManager;
    private SessionCache sessionCache;
    private Debug debug;

    /**
     * Constructor.
     *
     * @param debug the debug instance
     */
    @Inject
    public SessionResource(@Named("frRest") Debug debug, SessionQueryManager queryManager,
            SessionCache sessionCache) {
        this.queryManager = queryManager;
        this.debug = debug;
        this.sessionCache = sessionCache;
    }

    @Query
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {
        List<ResourceResponse> results = new ArrayList<>();
        final String realm = realmFor(context);
        final String apiOrg = DNMapper.orgNameToDN(realm);

        QueryFilter<JsonPointer> queryFilter = request.getQueryFilter();
        if (queryFilter != null) {
            return new NotSupportedException("Query filter not supported").asPromise();
        }

        String pattern = request.getQueryId();
        if (pattern == null || pattern.isEmpty()) {
            return new BadRequestException("Query ID is not specified").asPromise();
        }
        if (pattern.indexOf('*') >= 0) {
            return new BadRequestException("Query ID does not support wildcard").asPromise();
        }

        try {
            Collection<SessionInfo> infos = queryManager.getSessions(WebtopNaming.getAllServerIDs(), pattern);
            for (SessionInfo info : infos) {
                String userOrg = info.getProperties().get(ISAuthConstants.ORGANIZATION);
                if (apiOrg.equals(userOrg)) {
                    String userid = info.getProperties().get(ISAuthConstants.USER_ID);
                    JsonValue result = sessionToJsonValue(userid, realm, info);
                    results.add(newResourceResponse(userid, "0", result));
                }
            }
        } catch (SSOException e) {
            debug.error("SessionResource.queryCollection() :: Cannot QUERY sessions", e);
            return new InternalServerErrorException().asPromise();
        } catch (SMSException e) {
            debug.error("SessionResource.queryCollection() :: Cannot QUERY sessions", e);
            return new InternalServerErrorException().asPromise();
        } catch (SessionException e) {
            debug.error("SessionResource.queryCollection() :: Cannot QUERY sessions", e);
            return new InternalServerErrorException().asPromise();
        } catch (Exception e) {
            debug.error("SessionResource.queryCollection() :: Cannot QUERY sessions", e);
            return new InternalServerErrorException().asPromise();
        }
        return QueryResponsePresentation.perform(handler, request, results);
    }

    /**
     * Revokes the session associated with the session handle. This API does not check whether the realm
     * matches and whether the session handle is valid. Because if a remote session handle is passed, it
     * cannot be converted to the original session.
     *
     * @param context the request context
     * @param request the action request
     * @return A {@code Promise} containing the result of the operation.
     */
    @Action
    public Promise<ActionResponse, ResourceException> revoke(Context context, ActionRequest request) {
        JsonValue content = request.getContent();
        final SSOToken admin = context.asContext(SSOTokenContext.class).getCallerSSOToken();

        Set<String> keys = content.keys();
        for (String key : keys) {
            if (!FIELD_SESSION_HANDLE.equals(key)) {
                return new BadRequestException("Invalid field is specified").asPromise();
            }
        }

        JsonValue handleJson = content.get(FIELD_SESSION_HANDLE);
        if (!handleJson.isString()) {
            return new BadRequestException("Invalid field value syntax: '" + FIELD_SESSION_HANDLE + "'").asPromise();
        }
        String sessionHandle = handleJson.asString();
        if (sessionHandle == null) {
            return new BadRequestException(FIELD_SESSION_HANDLE + " is not specified").asPromise();
        }

        try {
            SessionID sid = new SessionID(sessionHandle);

            // Session Handle validation
            boolean isValid = false;
            try {
                if (sid.isSessionHandle() && sid.getExtension() != null) {
                    sid.validate();
                    isValid = true;
                }
            } catch (IllegalArgumentException e) {
                debug.warning("SessionResource.revoke() :: Session validation failed", e);
            } catch (SessionException e) {
                debug.warning("SessionResource.revoke() :: Session validation failed", e);
            }
            if (!isValid) {
                return new BadRequestException("Invalid field value syntax: '" + FIELD_SESSION_HANDLE + "'").asPromise();
            }

            Session session = new Session(sid);
            Session callerSession = sessionCache.getSession(new SessionID(admin.getTokenID().toString()));
            callerSession.destroySession(session);
        } catch (SessionException e) {
            debug.error("SessionResource.revoke() :: Cannot DESTROY session", e);
            return new InternalServerErrorException().asPromise();
        }
        return newActionResponse(json(object(field("success", true)))).asPromise();
    }

    private JsonValue sessionToJsonValue(String userid, String realm, SessionInfo info) throws SessionException {
        JsonValue result = json(object());
        result.add(FIELD_USER_NAME, userid);
        result.add(FIELD_SESSION_HANDLE, info.getProperties().get(SessionConstants.SESSION_HANDLE_PROP));
        result.add(FIELD_REALM, realm);
        result.add(FIELD_MAX_SESSION_EXPIRATION_TIME,
                DateTimeFormatter.ISO_INSTANT.format(
                        ZonedDateTime.ofInstant(
                                Instant.ofEpochSecond(info.getExpiryTime() / 1000), ZoneOffset.UTC)));
        result.add(FIELD_MAX_SESSION_TIME, info.getMaxTime());
        result.add(FIELD_IDLE_SESSION_EXPIRATION_TIME,
                DateTimeFormatter.ISO_INSTANT.format(
                        ZonedDateTime.ofInstant(
                                Instant.ofEpochSecond(info.getLastActivityTime() / 1000 + info.getMaxIdle() * 60),
                                        ZoneOffset.UTC)));
        result.add(FIELD_MAX_IDLE_TIME, info.getMaxIdle());
        return result;
    }
}
