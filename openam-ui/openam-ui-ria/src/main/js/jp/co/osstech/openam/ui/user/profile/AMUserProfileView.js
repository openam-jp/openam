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
    "underscore",
    "org/forgerock/commons/ui/common/main/Configuration",
    "org/forgerock/commons/ui/common/main/ValidatorsManager",
    "org/forgerock/commons/ui/common/util/ModuleLoader",
    "org/forgerock/commons/ui/user/profile/UserProfileView"
], function ($, _,
    Configuration,
    ValidatorsManager,
    ModuleLoader,
    UserProfileView) {

    var AMUserProfileView = Object.create(UserProfileView);

    AMUserProfileView.validationSuccessful =
        function (event) {
            if (!event || !event.target) {
                return $.Deferred().reject();
            }
            ModuleLoader.load("bootstrap")
            .then(function () {
                return $(event.target);
            })
            .then(
                _.bind(function (input) {
                    if (input.data()["bs.popover"]) {
                        input.popover("destroy");
                    }
                    input.parents(".form-group").removeClass("has-feedback has-error");

                    const form = input.closest("form");
                    if (form.attr("id") === "password") {
                        $(form).find("input[type='submit']").prop("disabled", !ValidatorsManager.formValidated(form));
                    } else {
                        const formData = _.mapValues(this.getFormContent(form[0]),
                            function (val) {
                                return typeof val === "string" ? val.trim() : val;
                            });
                        const currentData =
                            _(Configuration.loggedUser.toJSON())
                                .chain()
                                .pick(["username", "givenName", "sn", "mail", "telephoneNumber"])
                                .defaults({ "givenName" : "", "sn" : "", "mail" : "", "telephoneNumber" : "" })
                                .value();
                        if (!_.isEqual(formData, currentData) && ValidatorsManager.formValidated(form)) {
                            $(form).find("input[type='submit']").prop("disabled", false);
                        } else {
                            $(form).find("input[type='submit']").prop("disabled", true);
                        }
                    }
                }, this)
            );
        };

    return AMUserProfileView;
});
