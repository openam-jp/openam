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
package jp.co.osstech.openam.saml2.consent;

import static org.forgerock.openam.audit.AMAuditEventBuilderUtils.getUserId;

import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.forgerock.audit.events.AuditEvent;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;

import com.iplanet.sso.SSOToken;

import jp.co.osstech.openam.saml2.consent.AttributeConsent.ConsentType;

/**
 * The class <code>ConsentAuditor</code> is responsible for publishing audit
 * events in attribute consent steps.
 */
@Singleton
public class ConsentAuditor {

    private static final String TOPIC = "saml2consent";
    private static final String AGREED_EVENT_NAME = "AM-SAML2-CONSENT-AGREED";
    private static final String REJECTED_EVENT_NAME = "AM-SAML2-CONSENT-REJECTED";
    private static final String REJECTED = "REJECTED";

    private AuditEventPublisher auditEventPublisher;

    @Inject
    public ConsentAuditor(AuditEventPublisher auditEventPublisher) {
        this.auditEventPublisher = auditEventPublisher;
    }

    void auditAgree(
            SSOToken ssoToken,
            String realm,
            String idpEntityId,
            String spEntityId,
            List<String> attributes,
            ConsentType consentType) {
        ConsentAuditEventBuilder builder = new ConsentAuditEventBuilder();
        AuditEvent event = builder
                .eventName(AGREED_EVENT_NAME)
                .transactionId(AuditRequestContext.getTransactionIdValue())
                .userID(getUserId(ssoToken))
                .realm(realm)
                .idp(idpEntityId)
                .sp(spEntityId)
                .attributes(attributes)
                .consentType(consentType.toString())
                .toEvent();
        auditEventPublisher.tryPublish(TOPIC, event);
    }

    void auditReject(
            SSOToken ssoToken,
            String realm,
            String idpEntityId,
            String spEntityId,
            List<String> attributes) {
        ConsentAuditEventBuilder builder = new ConsentAuditEventBuilder();
        AuditEvent event = builder
                .eventName(REJECTED_EVENT_NAME)
                .transactionId(AuditRequestContext.getTransactionIdValue())
                .userID(getUserId(ssoToken))
                .realm(realm)
                .idp(idpEntityId)
                .sp(spEntityId)
                .attributes(attributes)
                .consentType(REJECTED)
                .toEvent();
        auditEventPublisher.tryPublish(TOPIC, event);
    }

}
