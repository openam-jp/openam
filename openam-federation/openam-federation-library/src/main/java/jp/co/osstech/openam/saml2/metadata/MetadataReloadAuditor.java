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
package jp.co.osstech.openam.saml2.metadata;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.forgerock.audit.events.AuditEvent;
import org.forgerock.openam.audit.AMActivityAuditEventBuilder;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;

@Singleton
class MetadataReloadAuditor {

    private static final String ACTIVITY_TOPIC = "activity";
    private static final String COMPLETE = "COMPLETE";
    private static final String ERROR = "ERROR";
    private static final String METADATA_RELOAD = "AM-METADATA-AUTO-RELOAD";

    private AuditEventPublisher auditEventPublisher;

    @Inject
    public MetadataReloadAuditor(AuditEventPublisher auditEventPublisher) {
        this.auditEventPublisher = auditEventPublisher;
    }

    void auditComplete(String realm) {
        String transactionID = AuditRequestContext.getTransactionIdValue();
        AMActivityAuditEventBuilder builder = new AMActivityAuditEventBuilder()
                .transactionId(transactionID)
                .objectId(transactionID)
                .realm(realm)
                .eventName(METADATA_RELOAD)
                .operation(COMPLETE);
        AuditEvent event = builder.toEvent();
        auditEventPublisher.tryPublish(ACTIVITY_TOPIC, event);
    }

    void auditError(String realm) {
        String transactionID = AuditRequestContext.getTransactionIdValue();
        AMActivityAuditEventBuilder builder = new AMActivityAuditEventBuilder()
                .transactionId(transactionID)
                .objectId(transactionID)
                .realm(realm)
                .eventName(METADATA_RELOAD)
                .operation(ERROR);
        AuditEvent event = builder.toEvent();
        auditEventPublisher.tryPublish(ACTIVITY_TOPIC, event);
    }

}
