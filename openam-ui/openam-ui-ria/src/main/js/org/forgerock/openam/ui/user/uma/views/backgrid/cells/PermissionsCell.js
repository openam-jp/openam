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
    "org/forgerock/openam/ui/common/util/BackgridUtils",

    // jquery dependencies
    "selectize"
], function ($, BackgridUtils) {
    return BackgridUtils.TemplateCell.extend({
        className: "permissions-cell",
        template: "templates/user/uma/backgrid/cell/PermissionsCell.html",
        onChange () {},
        rendered () {
            this.$el.find("select").selectize({
                dropdownParent: "body",
                onChange: this.onChange.bind(this)
            });
        }
    });
});

// TODO: Extend in future with ability to specify selected permissions (currently all are selected)
