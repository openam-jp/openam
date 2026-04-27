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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.sun.identity.shared.debug.Debug;

import jp.co.osstech.openam.saml2.consent.AttributeConsent.ConsentType;

/**
 * The class <code>AttributeConsentHistory</code> represents history of the user's
 * consents for some SP. This class determines whether a consent is required in
 * the current access.
 */
class AttributeConsentHistory {
    private static final Debug DEBUG = Debug.getInstance("SAML2AttributeConsent");

    private List<AttributeConsent> history;

    AttributeConsentHistory() {
        history = new ArrayList<>();
    }

    /**
     * Updates history of consents by given information.
     *
     * @param realm            Realm of the user
     * @param idpEntityId      EntityId of the IdP
     * @param spEntityId       EntityId of the SP
     * @param userName         User name
     * @param agreedAttributes Attribute names which user agreed to send to SP.
     * @param type             Consent type which user chose
     */
    void update(
            String realm,
            String idpEntityId,
            String spEntityId,
            String userName,
            Set<String> agreedAttributes,
            ConsentType type) {
        if (someSpSetAskNever(realm, idpEntityId, userName) && !ConsentType.ASK_NEVER.equals(type)) {
            cancelAllAskNever(realm, idpEntityId, userName);
        }
        AttributeConsent consent = new AttributeConsent(realm, idpEntityId, spEntityId, userName, agreedAttributes, type);
        updateHistory(consent);
    }

    /**
     * Check whether a consent is required in current access.
     *
     * @param realm                     Realm of the user.
     * @param idpEntityId               EntityId of the IdP
     * @param spEntityId                EntityId of the SP
     * @param userName                  User name
     * @param consentRequiredAttributes Attribute names that will be released to DP
     * @return Whether a consent is required or not.
     */
    boolean consentRequired(
            String realm,
            String idpEntityId,
            String spEntityId,
            String userName,
            Set<String> consentRequiredAttributes) {
        if (someSpSetAskNever(realm, idpEntityId, userName)) {
            return false;
        }
        if (spNotInHistory(realm, idpEntityId, spEntityId, userName)) {
            DEBUG.message("History doesn't contain consent for the SP: {}.", spEntityId);
            return true;
        }
        if (spSetAskAgain(realm, idpEntityId, spEntityId, userName)) {
            DEBUG.message("ASK_AGAIN is set for SP: {}.", spEntityId);
            return true;
        }
        if (allAttributesAlreadyAgreed(realm, idpEntityId, spEntityId, userName, consentRequiredAttributes)) {
            DEBUG.message("All released attributes are already agreed.");
            return false;
        }
        return true;
    }

    private boolean someSpSetAskNever(String realm, String idpEntityId, String userName) {
        List<AttributeConsent> matchedHistory = findHistory(realm, idpEntityId, userName);
        for (AttributeConsent consent : matchedHistory) {
            if (consent.getConsentType().equals(ConsentType.ASK_NEVER)) {
                DEBUG.message("ASK_NEVER is set for SP: {}.", consent.getSpEntityId());
                return true;
            }
        }
        return false;
    }

    private boolean spSetAskAgain(String realm, String idpEntityId, String spEntityId, String userName) {
        AttributeConsent consent = findHistory(realm, idpEntityId, spEntityId, userName);
        if (consent == null) {
            return false;
        }
        return consent.getConsentType().equals(ConsentType.ASK_AGAIN);
    }

    private boolean spNotInHistory(String realm, String idpEntityId, String spEntityId, String userName) {
        return findHistory(realm, idpEntityId, spEntityId, userName) == null;
    }

    private boolean allAttributesAlreadyAgreed(String realm, String idpEntityId, String spEntityId, String userName,
            Set<String> releasedAttributes) {
        AttributeConsent consent = findHistory(realm, idpEntityId, spEntityId, userName);
        Set<String> agreedAttributes = consent.getAgreedAttributes();
        for (String releasedAttribute : releasedAttributes) {
            if (!agreedAttributes.contains(releasedAttribute)) {
                DEBUG.message("Attribute: {} is not agreed yet.", releasedAttribute);
                return false;
            }
        }
        return true;
    }

    private void cancelAllAskNever(String realm, String idpEntityId, String userName) {
        List<AttributeConsent> matchedHistory = findHistory(realm, idpEntityId, userName);
        for (AttributeConsent currentConsent : matchedHistory) {
            if (currentConsent.getConsentType().equals(ConsentType.ASK_NEVER)) {
                String spEntityId = currentConsent.getSpEntityId();
                Set<String> attributes = currentConsent.getAgreedAttributes();
                AttributeConsent newConsent = new AttributeConsent(realm, idpEntityId, spEntityId, userName, attributes,
                        ConsentType.ASK_AGAIN);
                updateHistory(newConsent);
            }
        }
    }

    private List<AttributeConsent> findHistory(String realm, String idpEntityId, String userName) {
        List<AttributeConsent> matched = new ArrayList<>();
        for (AttributeConsent consent : history) {
            if (consent.getRealm().equals(realm)
                    && consent.getIdpEntityId().equals(idpEntityId)
                    && consent.getUserName().equals(userName)) {
                matched.add(consent);
            }
        }
        return matched;
    }

    private AttributeConsent findHistory(String realm, String idpEntityId, String spEntityId, String userName) {
        for (AttributeConsent consent : history) {
            if (consent.getRealm().equals(realm)
                    && consent.getIdpEntityId().equals(idpEntityId)
                    && consent.getSpEntityId().equals(spEntityId)
                    && consent.getUserName().equals(userName)) {
                return consent;
            }
        }
        return null;
    }

    private void updateHistory(AttributeConsent newConsent) {
        AttributeConsent current = findHistory(
                newConsent.getRealm(),
                newConsent.getIdpEntityId(),
                newConsent.getSpEntityId(),
                newConsent.getUserName());
        if (current != null) {
            history.remove(current);
        }
        history.add(newConsent);
    }
}
