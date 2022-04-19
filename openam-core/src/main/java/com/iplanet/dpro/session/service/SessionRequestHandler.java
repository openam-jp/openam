/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2005 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * $Id: SessionRequestHandler.java,v 1.9 2009/04/02 04:11:44 ericow Exp $
 *
 * Portions Copyrighted 2011-2016 ForgeRock AS.
 * Portions Copyrighted 2021 OSSTech Corporation
 */
package com.iplanet.dpro.session.service;

import static org.forgerock.openam.audit.AuditConstants.Component.SESSION;
import static org.forgerock.openam.session.SessionConstants.SESSION_DEBUG;
import static org.forgerock.openam.session.SessionConstants.TOKEN_RESTRICTION_PROP;

import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.session.SessionCache;
import org.forgerock.openam.session.SessionCookies;
import org.forgerock.openam.session.SessionPLLSender;
import org.forgerock.openam.session.SessionServiceURLService;
import org.forgerock.openam.sso.providers.stateless.StatelessSessionFactory;

import com.google.inject.Key;
import com.google.inject.name.Names;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.dpro.session.Session;
import com.iplanet.dpro.session.SessionException;
import com.iplanet.dpro.session.SessionID;
import com.iplanet.dpro.session.share.SessionBundle;
import com.iplanet.dpro.session.share.SessionInfo;
import com.iplanet.dpro.session.share.SessionRequest;
import com.iplanet.dpro.session.share.SessionResponse;
import com.iplanet.services.comm.server.PLLAuditor;
import com.iplanet.services.comm.server.RequestHandler;
import com.iplanet.services.comm.share.Request;
import com.iplanet.services.comm.share.Response;
import com.iplanet.services.comm.share.ResponseSet;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.session.util.RestrictedTokenAction;
import com.sun.identity.session.util.RestrictedTokenContext;
import com.sun.identity.session.util.SessionUtils;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;

public class SessionRequestHandler implements RequestHandler {

    private final SessionService sessionService;
    private final Debug sessionDebug;
    private final SessionServerConfig serverConfig;
    private final SessionServiceConfig serviceConfig;
    private final StatelessSessionFactory statelessSessionFactory;

    /*
     * Added this property to block registration of the global notification
     * listener (AddListenerOnAllSessions);
     */
    private static Boolean enableAddListenerOnAllSessions = null;
    private SSOToken clientToken = null;

    private static final SessionServiceURLService SESSION_SERVICE_URL_SERVICE = InjectorHolder.getInstance(SessionServiceURLService.class);
    private static final SessionCookies sessionCookies
            = InjectorHolder.getInstance(SessionCookies.class);
    private static final SessionCache sessionCache = InjectorHolder.getInstance(SessionCache.class);
    private static final SessionPLLSender sessionPLLSender = InjectorHolder.getInstance(SessionPLLSender.class);

    public SessionRequestHandler() {
        sessionService = InjectorHolder.getInstance(SessionService.class);
        sessionDebug =  InjectorHolder.getInstance(Key.get(Debug.class, Names.named(SESSION_DEBUG)));
        serverConfig = InjectorHolder.getInstance(SessionServerConfig.class);
        serviceConfig = InjectorHolder.getInstance(SessionServiceConfig.class);
        statelessSessionFactory = InjectorHolder.getInstance(StatelessSessionFactory.class);
    }

    /**
     * Understands how to resolve a Token based on its SessionID.
     *
     * Stateless Sessions by their very nature do not need to be stored in memory, and so
     * can be resolved in a different way to Stateful Sessions.
     *
     * @param sessionID Non null Session ID.
     *
     * @return Null if no matching Session could be found, otherwise a non null
     * Session instance.
     *
     * @throws SessionException If there was an error resolving the Session.
     */
    private Session resolveSession(SessionID sessionID) throws SessionException {
        if (statelessSessionFactory.containsJwt(sessionID)) {
            return statelessSessionFactory.generate(sessionID);
        }
        return sessionCache.getSession(sessionID);
    }

    public ResponseSet process(PLLAuditor auditor,
                               List<Request> requests,
                               HttpServletRequest servletRequest,
                               HttpServletResponse servletResponse,
                               ServletContext servletContext) {
        ResponseSet rset = new ResponseSet(SessionService.SESSION_SERVICE);

        auditor.setComponent(SESSION);
        for (Request req : requests) {
            Response res = processRequest(auditor, req, servletRequest, servletResponse);
            rset.addResponse(res);
        }

        return rset;
    }

    private Response processRequest(
            final PLLAuditor auditor,
            final Request req,
            final HttpServletRequest servletRequest,
            final HttpServletResponse servletResponse) {

        final SessionRequest sreq = SessionRequest.parseXML(req.getContent());
        auditor.setMethod(sreq.getMethodName());
        SessionResponse sres = new SessionResponse(sreq.getRequestID(), sreq.getMethodID());

        Object context;
        try {
            // use remote client IP as default RestrictedToken context
            context = SessionUtils.getClientAddress(servletRequest);
            this.clientToken = null;
        } catch (Exception ex) {
            sessionDebug.error("SessionRequestHandler encounterd exception", ex);
            sres.setException(ex.getMessage());
            return auditedExceptionResponse(auditor, sres);
        }

        String requester = sreq.getRequester();
        if (requester != null) {
            try {
                context = RestrictedTokenContext.unmarshal(requester);

                if (context instanceof SSOToken) {
                    SSOTokenManager ssoTokenManager = SSOTokenManager.getInstance();
                    SSOToken adminToken = (SSOToken)context;

                    if (!ssoTokenManager.isValidToken(adminToken)) {
                        sres.setException(SessionBundle.getString("appTokenInvalid") + requester);
                        return auditedExceptionResponse(auditor, sres);
                    }

                    this.clientToken = (SSOToken)context;
                }
            } catch (Exception ex) {
                if (sessionDebug.warningEnabled()) {
                    sessionDebug.warning(
                            "SessionRequestHandler.processRequest:"
                                    + "app token invalid, sending Session response"
                                    +" with Exception");
                }
                sres.setException(SessionBundle.getString("appTokenInvalid") + requester);
                return auditedExceptionResponse(auditor, sres);
            }
        }

        try {
            sres = (SessionResponse) RestrictedTokenContext.doUsing(context,
                    new RestrictedTokenAction() {
                        public Object run() throws Exception {
                            return processSessionRequest(auditor, sreq, servletRequest, servletResponse);
                        }
                    });
        } catch (Exception ex) {
            sessionDebug.error("SessionRequestHandler encounterd exception", ex);
            sres.setException(ex.getMessage());
        }

        if (sres.getException() == null) {
            auditor.auditAccessSuccess();
        } else {
            auditor.auditAccessFailure(sres.getException());
        }

        return new Response(sres.toXMLString());
    }

    private Response auditedExceptionResponse(PLLAuditor auditor, SessionResponse sres) {
        auditor.auditAccessAttempt();
        auditor.auditAccessFailure(sres.getException());
        return new Response(sres.toXMLString());
    }

    private SessionResponse processSessionRequest(PLLAuditor auditor,
                                                  SessionRequest req,
                                                  HttpServletRequest servletRequest,
                                                  HttpServletResponse servletResponse) {
        SessionResponse res = new SessionResponse(req.getRequestID(), req.getMethodID());
        SessionID sid = new SessionID(req.getSessionID());
        Session requesterSession = null;

        try {
            /* common processing by groups of methods */
            switch (req.getMethodID()) {
            /*
             * in this group of methods the request is targeting either all
             * LOCAL sessions or a single local session identified by another
             * request parameter sid in this case is only used to authenticate
             * the operation Session pointed by sid is not expected to be local
             * to this server (although it might)
             */
                case SessionRequest.GetValidSessions:
                case SessionRequest.AddSessionListenerOnAllSessions:
                case SessionRequest.GetSessionCount:
                    /*
                     * note that the purpose of the following is just to check the
                     * authentication of the caller (which can also be used as a
                     * filter for the operation scope!)
                     */
                    requesterSession = resolveSession(sid);
                    auditAccessAttempt(auditor, requesterSession);
                    /*
                     * also check that sid is not a restricted token
                     */
                    if (requesterSession.getProperty(TOKEN_RESTRICTION_PROP) != null) {
                        res.setException(sid + " " + SessionBundle.getString("noPrivilege"));
                        return res;
                    }

                    break;

            /*
             * In this group request is targeting a single session identified by
             * sid which is supposed to be hosted by this server instance sid is
             * used both as an id of a session and to authenticate the operation
             * (performed on own session)
             */
                case SessionRequest.GetSession:
                case SessionRequest.Logout:
                case SessionRequest.AddSessionListener:
                case SessionRequest.SetProperty:
                case SessionRequest.DestroySession:
                    if (req.getMethodID() == SessionRequest.DestroySession) {
                        requesterSession = resolveSession(sid);
                        auditAccessAttempt(auditor, requesterSession);
                        /*
                         * also check that sid is not a restricted token
                         */
                        if (requesterSession.getProperty(TOKEN_RESTRICTION_PROP) != null) {
                            res.setException(sid + " " + SessionBundle.getString("noPrivilege"));
                            return res;
                        }
                        sid = new SessionID(req.getDestroySessionID());
                    } else {
                        try {
                            auditAccessAttempt(auditor, resolveSession(sid));
                        } catch (SessionException ignored) {
                            // ignore, we'll log the access attempt without session properties
                            auditor.auditAccessAttempt();
                        }
                    }

                    if (req.getMethodID() == SessionRequest.SetProperty) {
                        /*
                         * This fix is to avoid clients sneaking in to set
                         * protected properties in server-2 or so through
                         * server-1. Short circuit this operation without
                         * forwarding it further.
                         */
                        try {
                            SessionUtils.checkPermissionToSetProperty(
                                    this.clientToken, req.getPropertyName(),
                                    req.getPropertyValue());
                        } catch (SessionException se) {
                            if (sessionDebug.warningEnabled()) {
                                sessionDebug.warning(
                                        "SessionRequestHandler.processRequest:"
                                                + "Client does not have permission to set"
                                                + " - property key = " + req.getPropertyName()
                                                + " : property value = " + req.getPropertyValue());
                            }

                            res.setException(sid + " " + SessionBundle.getString("noPrivilege"));
                            return res;
                        }
                    }

                    if (!serviceConfig.isSessionFailoverEnabled()) {
                        // TODO check how this behaves in non-session failover case
                        URL originService = SESSION_SERVICE_URL_SERVICE.getSessionServiceURL(sid);

                        if (!serverConfig.isLocalSessionService(originService)) {
                            if (!serverConfig.isSiteEnabled()) {
                                String siteID = sid.getExtension().getSiteID();
                                if (siteID != null) {
                                    String primaryID = sid.getExtension().getPrimaryID();
                                    String localServerID = serverConfig.getLocalServerID();
                                    if ( (primaryID != null) && (localServerID != null) )
                                    {
                                        if (primaryID.equals(localServerID)) {
                                            throw new SessionException("invalid session id");
                                        }
                                    }
                                }
                            } else {
                                return forward(originService, req);
                            }
                        }
                    } else {
                        if (serviceConfig.isUseInternalRequestRoutingEnabled()) {
                            // first try
                            String hostServerID = sessionService.getCurrentHostServer(sid);

                            if (!serverConfig.isLocalServer(hostServerID)) {
                                try {
                                    return forward(SESSION_SERVICE_URL_SERVICE.getSessionServiceURL(hostServerID), req);
                                } catch (SessionException se) {
                                    // attempt retry
                                    if (!sessionService.checkServerUp(hostServerID)) {
                                        // proceed with failover
                                        String retryHostServerID = sessionService.getCurrentHostServer(sid);
                                        if (retryHostServerID.equals(hostServerID)) {
                                            throw se;
                                        } else {
                                            // we have a shot at retrying here
                                            // if it is remote, forward it
                                            // otherwise treat it as a case of local
                                            // case
                                            if (!serverConfig.isLocalServer(retryHostServerID)) {
                                                return forward(SESSION_SERVICE_URL_SERVICE.getSessionServiceURL(retryHostServerID), req);
                                            }
                                        }
                                    } else {
                                        throw se;
                                    }
                                }
                            }
                        } else {
                            // Likely an unreachable code block [AME-5701]:
                            // SessionServiceConfig sets useInternalRequestRouting=true if SMS property
                            // "iplanet-am-session-sfo-enabled" is true
                            // To enter this block, SMS value "iplanet-am-session-sfo-enabled" must be false
                            // and the following System Properties must be set:
                            // com.iplanet.am.session.failover.useInternalRequestRouting=false
                            // iplanet-am-session-sfo-enabled=true (in direct contradiction to SMS property with same name)
                            throw new AssertionError("Unreachable code");
                        }

                    /*
                     * We determined that this server is the host and the
                     * session must be found(or recovered) locally
                     */

                    /*
                     * if session is not already present locally attempt to
                     * recover session if in failover mode
                     */
                        if (!sessionService.isSessionPresent(sid)) {
                            if (sessionService.recoverSession(sid) == null) {
                            /*
                             * if not in failover mode or recovery was not
                             * successful return an exception
                             */

                            /*
                             * !!!!! IMPORTANT !!!!! DO NOT REMOVE "sid" FROM
                             * EXCEPTIONMESSAGE Logic kludge in legacy Agent 2.0
                             * code will break If it can not find SID value in
                             * the exception message returned by Session
                             * Service. This dependency should be eventually
                             * removed once we migrate customers to a newer
                             * agent code base or switch to a new version of
                             * Session Service interface
                             */
                                res.setException(sid + " " + SessionBundle.getString("sessionNotObtained"));
                                return res;
                            }
                        }
                    }

                    break;
                default:
                    res.setException(sid + " " + SessionBundle.getString("unknownRequestMethod"));
                    return res;
            }

            /*
             * request method-specific processing
             */
            switch (req.getMethodID()) {
                case SessionRequest.GetSession:
                    try {
                        if (statelessSessionFactory.containsJwt(sid)) {
                            // We need to validate the session before creating the sessioninfo to ensure that the
                            // stateless session hasn't timed out yet, and hasn't  been blacklisted either.
                            SSOTokenManager tokenManager = SSOTokenManager.getInstance();
                            final SSOToken statelessToken = tokenManager.createSSOToken(req.getSessionID());
                            if (!tokenManager.isValidToken(statelessToken)) {
                                throw new SessionException(SessionBundle.getString("invalidSessionID")
                                        + req.getSessionID());
                            }
                        }
                        res.addSessionInfo(sessionService.getSessionInfo(sid, req.getResetFlag()));
                    } catch (SSOException ssoe) {
                        res.setException(SessionBundle.getString("invalidSessionID") + req.getSessionID());
                    }
                    break;

                case SessionRequest.GetValidSessions:
                    String pattern = req.getPattern();
                    List<SessionInfo> infos = null;
                    int status[] = { 0 };
                    infos = sessionService.getValidSessions(requesterSession, pattern, status);
                    res.setStatus(status[0]);
                    res.setSessionInfo(infos);
                    break;

                case SessionRequest.DestroySession:
                    sessionService.destroySession(requesterSession, new SessionID(req.getDestroySessionID()));
                    break;

                case SessionRequest.Logout:
                    sessionService.logout(sid);
                    break;

                case SessionRequest.AddSessionListener:
                    sessionService.addSessionListener(sid, req.getNotificationURL());
                    break;

                case SessionRequest.AddSessionListenerOnAllSessions:
                    /**
                     * Cookie Hijacking fix to disable adding of Notification
                     * Listener for ALL the sessions over the network to the server
                     * instance specified by Notification URL This property can be
                     * added and set in the AMConfig.properties file should there be
                     * a need to add Notification Listener to ALL the sessions. The
                     * default value of this property is FALSE
                     */
                    if (getEnableAddListenerOnAllSessions()) {
                        sessionService.addSessionListenerOnAllSessions(requesterSession, req.getNotificationURL());
                    }
                    break;

                case SessionRequest.SetProperty:
                    sessionService.setExternalProperty(this.clientToken, sid, req.getPropertyName(), req.getPropertyValue());
                    break;

                case SessionRequest.GetSessionCount:
                    String uuid = req.getUUID();
                    Object sessions = SessionCount.getSessionsFromLocalServer(requesterSession, uuid);

                    if (sessions != null) {
                        res.setSessionsForGivenUUID((Map) sessions);
                    }

                    break;

                default:
                    res.setException(sid + " " + SessionBundle.getString("unknownRequestMethod"));
                    break;
            }
        } catch (SessionException se) {
            sessionDebug.message("processSessionRequest caught exception: {}", se.getMessage(), se);
            res.setException(sid + " " + se.getMessage());
        }
        return res;
    }

    private void auditAccessAttempt(PLLAuditor auditor, Session session) {
        try {
            auditor.setUserId(session.getClientID());
            auditor.setTrackingId(session.getProperty(Constants.AM_CTX_ID));
            auditor.setRealm(session.getProperty(Constants.ORGANIZATION));
        } catch (SessionException ignored) {
            // Don't audit with session information.
        }
        auditor.auditAccessAttempt();
    }

    private SessionResponse forward(URL svcurl, SessionRequest sreq)
            throws SessionException {
        try {
            Object context = RestrictedTokenContext.getCurrent();

            if (context != null) {
                sreq.setRequester(RestrictedTokenContext.marshal(context));
            }

            SessionResponse sres = sessionPLLSender.sendPLLRequest(svcurl, sreq);

            if (sres.getException() != null) {
                throw new SessionException(sres.getException());
            }
            return sres;
        } catch (SessionException se) {
            throw se;
        } catch (Exception ex) {
            throw new SessionException(ex);
        }
    }

    private static boolean getEnableAddListenerOnAllSessions() {
        if (enableAddListenerOnAllSessions == null) {
            enableAddListenerOnAllSessions = Boolean.valueOf(SystemProperties
                    .get(Constants.ENABLE_ADD_LISTENER_ON_ALL_SESSIONS));
        }

        return enableAddListenerOnAllSessions.booleanValue();
    }
}
