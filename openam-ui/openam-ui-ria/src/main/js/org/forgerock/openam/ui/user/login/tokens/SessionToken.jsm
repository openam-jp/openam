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
 * Copyright 2016 ForgeRock AS.
 * Portions copyright 2020 Open Source Solution Technology Corporation
 */

/**
 * The Session Token (tokenId) used by OpenAM to track an authenticated session.
 * @module org/forgerock/openam/ui/user/login/tokens/SessionToken
 */

import _ from "lodash";
import CookieHelper from "org/forgerock/commons/ui/common/util/CookieHelper";
import Configuration from "org/forgerock/commons/ui/common/main/Configuration";

function cookieName () {
    return Configuration.globalData.auth.cookieName;
}

function cookieDomains () {
    return Configuration.globalData.auth.cookieDomains;
}

function secureCookie () {
    return Configuration.globalData.secureCookie;
}

function cookieSameSite () {
    if (_.has(Configuration, `globalData.cookieSamesiteMap[${cookieName()}]`)) {
        return Configuration.globalData.cookieSamesiteMap[cookieName()];
    }
}

export function set (token) {
    return CookieHelper.setCookie(cookieName(), token, "", "/", cookieDomains(), secureCookie(), cookieSameSite());
}

export function get () {
    return CookieHelper.getCookie(cookieName());
}
