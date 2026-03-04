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
 * Copyright 2026 OSSTech Corporation
 */

define([
    "jquery",
    "lodash",
    "org/forgerock/commons/ui/user/profile/UserProfileKBAView",
    "jp/co/osstech/openam/ui/user/profile/AMUserProfileView"
], function ($, _,
    UserProfileKBAView,
    AMUserProfileView) {

    var AMUserProfileKBAView = Object.create(UserProfileKBAView);

    AMUserProfileKBAView.validationSuccessful =
        function (event) {
            if (!event || !event.target) {
                return $.Deferred().reject();
            }
            const target = $(event.target);
            const form = target.closest("form");
            if (form.attr("id") === "KBA") {
                UserProfileKBAView.validationSuccessful.call(this, event);
            } else {
                AMUserProfileView.validationSuccessful.call(this, event);
            }
        };

    return AMUserProfileKBAView;
});

