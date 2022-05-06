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
 */

define([
    "jquery-migrate",
    "lodash",
    "org/forgerock/commons/ui/common/components/Messages",
    "org/forgerock/commons/ui/common/main/AbstractView",
    "org/forgerock/openam/ui/admin/services/realm/AuthenticationService",
    "org/forgerock/openam/ui/admin/utils/FormHelper",
    "org/forgerock/openam/ui/common/util/array/arrayify",
    "org/forgerock/openam/ui/common/util/Promise"
], function ($, _, Messages, AbstractView, AuthenticationService, FormHelper, arrayify, Promise) {
    function getChainNameFromElement (element) {
        return $(element).data().chainName;
    }
    function performDeleteChains (realmPath, names) {
        return Promise.all(arrayify(names).map(function (name) {
            return AuthenticationService.authentication.chains.remove(realmPath, name);
        }));
    }

    var ChainsView = AbstractView.extend({
        template: "templates/admin/views/realms/authentication/ChainsTemplate.html",
        events: {
            "change input[data-chain-name]" : "chainSelected",
            "click  [data-delete-chain]"    : "onDeleteSingle",
            "click  [data-delete-chains]"   : "onDeleteMultiple",
            "click  [data-select-all]"      : "selectAll"
        },
        chainSelected (event) {
            var hasChainsSelected = this.$el.find("input[type=checkbox][data-chain-name]").is(":checked"),
                row = $(event.currentTarget).closest("tr"),
                checked = $(event.currentTarget).is(":checked");

            this.$el.find("[data-delete-chains]").prop("disabled", !hasChainsSelected);

            if (checked) {
                row.addClass("selected");
            } else {
                row.removeClass("selected");
                this.$el.find("[data-select-all]").prop("checked", false);
            }
        },
        selectAll (event) {
            var checked = $(event.currentTarget).is(":checked");
            this.$el.find(".sorted-chains input[type=checkbox][data-chain-name]:not(:disabled)")
                .prop("checked", checked);
            if (checked) {
                this.$el.find(".sorted-chains:not(.default-config-row)").addClass("selected");
            } else {
                this.$el.find(".sorted-chains").removeClass("selected");
            }
            this.$el.find("[data-delete-chains]").prop("disabled", !checked);
        },
        onDeleteSingle (event) {
            event.preventDefault();

            FormHelper.showConfirmationBeforeDeleting({
                type: $.t("console.authentication.common.chain")
            }, _.bind(this.deleteChain, this, event));
        },
        onDeleteMultiple (event) {
            event.preventDefault();

            var selectedChains = this.$el.find(".sorted-chains input[type=checkbox][data-chain-name]:checked");

            FormHelper.showConfirmationBeforeDeleting({
                message: $.t("console.authentication.chains.confirmDeleteSelected", { count: selectedChains.length })
            }, _.bind(this.deleteChains, this, event, selectedChains));
        },
        deleteChain (event) {
            var self = this,
                element = event.currentTarget,
                name = getChainNameFromElement(event.currentTarget);

            $(element).prop("disabled", true);

            performDeleteChains(this.data.realmPath, name).then(function () {
                self.render([self.data.realmPath]);
            }, function (response) {
                Messages.addMessage({
                    type: Messages.TYPE_DANGER,
                    response
                });
                $(element).prop("disabled", false);
            });
        },
        deleteChains (event, selectedChains) {
            var self = this,
                element = event.currentTarget,
                names = _(selectedChains).toArray().map(getChainNameFromElement).value();

            $(element).prop("disabled", true);

            performDeleteChains(this.data.realmPath, names).then(function () {
                self.render([self.data.realmPath]);
            }, function (response) {
                Messages.addMessage({
                    type: Messages.TYPE_DANGER,
                    response
                });
                $(element).prop("disabled", false);
            });
        },
        render (args, callback) {
            var self = this,
                sortedChains = [];

            this.data.realmPath = args[0];

            AuthenticationService.authentication.chains.all(this.data.realmPath).then(function (data) {
                _.each(data.values.result, function (obj) {
                    // Add default chains to top of list.
                    if (obj.active) {
                        sortedChains.unshift(obj);
                    } else {
                        sortedChains.push(obj);
                    }
                });
                self.data.sortedChains = sortedChains;
                self.parentRender(function () {
                    if (callback) {
                        callback();
                    }
                });
            }, function (response) {
                Messages.addMessage({
                    type: Messages.TYPE_DANGER,
                    response
                });
            });
        }
    });

    return ChainsView;
});
