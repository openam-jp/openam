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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2026 OSSTech Corporation
 */

define([
    "lodash",
    "org/forgerock/commons/ui/common/main/Configuration",
    "org/forgerock/commons/ui/common/util/Constants",
    "org/forgerock/commons/ui/user/delegates/KBADelegate",
    "org/forgerock/openam/ui/common/util/RealmHelper"
], function (_, Configuration, Constants, KBADelegate, RealmHelper) {

    KBADelegate.serviceUrl = RealmHelper.decorateURIWithSubRealm(`/${Constants.context}/json/__subrealm__/${
            Constants.SELF_SERVICE_CONTEXT
        }`);
    KBADelegate.baseEntity = RealmHelper.decorateURIWithSubRealm(`json/__subrealm__/${Constants.SELF_SERVICE_CONTEXT}`);

    KBADelegate.saveInfo = function (user) {
        return this.serviceCall({
            "type": "PATCH",
            "url": "user/" + Configuration.loggedUser.id,
            "data": JSON.stringify(
                _(user)
                 .map(function (value, key) {
                     return {
                         "operation": "replace",
                         "field": "/" + key,
                         // replace the whole value, rather than just the parts that have changed,
                         // since there is no consistent way to target items in a set across the stack
                         "value": value
                     };
                 })
            )
        }).then(function (updatedUser) {
            updatedUser.roles = Configuration.loggedUser.get("roles");
            Configuration.loggedUser.set(Configuration.loggedUser.parse(updatedUser));
        });
    };

    return KBADelegate;
});
