/**
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
 * Portions copyright 2014-2016 ForgeRock AS.
 * Portions copyright 2026 OSSTech Corporation
 */

define([
    "jquery",
    "org/forgerock/commons/ui/common/main/AbstractDelegate",
    "org/forgerock/commons/ui/common/main/Configuration",
    "org/forgerock/commons/ui/common/util/Constants",
    "org/forgerock/commons/ui/common/util/URIUtils",
    "org/forgerock/openam/ui/common/services/ServerService"
], function ($, AbstractDelegate, Configuration, Constants, URIUtils, ServerService) {
    var obj = new AbstractDelegate(`${Constants.host}/${Constants.context}`),
        setRequireMapConfig = function (serverInfo) {
            require.config({ "map": { "*": {
                "UserProfileView" : (serverInfo.kbaEnabled === "true"
                    ? "jp/co/osstech/openam/ui/user/profile/AMUserProfileKBAView"
                    : "jp/co/osstech/openam/ui/user/profile/AMUserProfileView")
            } } });

            return serverInfo;
        };

    /**
     * Makes a HTTP request to the server to get its configuration
     * @param {Function} successCallback Success callback function
     * @param {Function} errorCallback   Error callback function
     */
    obj.getConfiguration = function (successCallback, errorCallback) {
        ServerService.getConfiguration({ suppressEvents: true }).then(function (response) {
            setRequireMapConfig(response);
            successCallback(response);
        }, errorCallback);
    };

    /**
     * Checks for a change of realm
     * @returns {Promise} If the realm has changed then a promise that will contain the response from the
     * serverinfo/* REST call, otherwise an empty successful promise.
     */
    obj.checkForDifferences = function () {
        if (Configuration.globalData.auth.authRealm !== Configuration.globalData.auth.sessionRealm) {
            return ServerService.getConfiguration({
                errorsHandlers: {
                    "unauthorized": { status: "401" },
                    "Bad Request": {
                        status: "400",
                        event: Constants.EVENT_INVALID_REALM
                    }
                }
            }).then(setRequireMapConfig);
        } else {
            return $.Deferred().resolve();
        }
    };

    return obj;
});
