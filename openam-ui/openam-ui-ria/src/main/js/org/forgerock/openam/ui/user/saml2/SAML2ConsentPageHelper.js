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

/**
 * @module org/forgerock/openam/ui/user/saml2/SAML2ConsentPageHelper
 */
define([
    "lodash",
    "org/forgerock/commons/ui/common/main/AbstractDelegate",
    "org/forgerock/commons/ui/common/util/Constants",
    "org/forgerock/openam/ui/common/models/JSONValues",
    "org/forgerock/commons/ui/common/main/ServiceInvoker",
    "org/forgerock/openam/ui/common/util/RealmHelper"
], function (_, AbstractDelegate, Constants, JSONValues, ServiceInvoker, RealmHelper) {

    const contextPath = "saml2";
    const uriContextParts = Constants.context.split("/");
    const uriContext = uriContextParts.slice(0, uriContextParts.indexOf(contextPath));
    const obj = new AbstractDelegate(`${Constants.host}/${uriContext}/json`);

    obj.collectUIInfo = (realm, spEntityId) => {
        ServiceInvoker.updateConfigurationCallback({});
        var encodedRealm = "";
        if (realm !== "/") {
            encodedRealm = RealmHelper.encodeRealm(realm);
        }
        return obj.serviceCall({
            url: `${encodedRealm}/saml2/metadata/uiinfo?entityID=${encodeURIComponent(spEntityId)}`,
            type: "GET",
            headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
            suppressEvents: true
        });
    };

    obj.getConsentRequiredAttribute = (
        realm,
        consentID,
        forceConsent
    ) => {
        const encryptedHistory = obj.getStoredHistory(realm);
        const requestData = {
            history: encryptedHistory,
            forceConsent
        };
        ServiceInvoker.updateConfigurationCallback({});
        return obj.serviceCall({
            url: `/saml2/consent/${consentID}?_action=getAttributes`,
            type: "POST",
            headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
            suppressEvents: true,
            data: new JSONValues(requestData).toJSON()
        });
    };

    obj.agree = (
        realm,
        consentID,
        attributes,
        consentType,
    ) => {
        const encryptedHistory = obj.getStoredHistory(realm);
        const requestData = {
            type: consentType,
            attributes,
            history: encryptedHistory
        };
        ServiceInvoker.updateConfigurationCallback({});
        return obj.serviceCall({
            url: `/saml2/consent/${consentID}?_action=agree`,
            type: "POST",
            headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
            suppressEvents: true,
            data: new JSONValues(requestData).toJSON()
        }).done((response) => {
            const newHistory = response.history;
            obj.storeHistory(realm, newHistory);
        });
    };

    obj.reject = (
        realm,
        consentID,
        attributes,
    ) => {
        const encryptedHistory = obj.getStoredHistory(realm);
        const requestData = {
            attributes,
            history: encryptedHistory
        };
        ServiceInvoker.updateConfigurationCallback({});
        return obj.serviceCall({
            url: `/saml2/consent/${consentID}?_action=reject`,
            type: "POST",
            headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
            suppressEvents: true,
            data: new JSONValues(requestData).toJSON()
        }).done((response) => {
            const newHistory = response.history;
            obj.storeHistory(realm, newHistory);
        });
    };

    obj.isSameContextPath = (originalRequestURI) => {
        const redirectURI = decodeURI(originalRequestURI);
        return redirectURI.indexOf(`/${uriContext}`) === 0;
    };

    obj.returnToSAMLFlow = (originalRequestURI, consentID) => {
        let destination = decodeURI(originalRequestURI);
        if (destination.indexOf("?") === -1) {
            destination = `${destination}?consentID=${consentID}`;
        } else {
            destination = `${destination}&consentID=${consentID}`;
        }
        window.location.href = destination;
    };

    const localStorageKeyPrefix = "saml2attributeConsent-";
    const realmToStorageKey = (realm) => `${localStorageKeyPrefix}${realm}`;

    obj.storeHistory = (realm, encryptedHistory) => {
        const key = realmToStorageKey(realm);
        localStorage.setItem(key, encryptedHistory);
    };

    obj.getStoredHistory = (realm) => {
        const key = realmToStorageKey(realm);
        return localStorage.getItem(key);
    };

    return obj;
});
