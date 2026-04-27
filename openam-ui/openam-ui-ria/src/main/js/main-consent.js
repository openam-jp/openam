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

require.config({
    map: {
        "*": {
            "ThemeManager": "org/forgerock/openam/ui/common/util/ThemeManager",
            "Router": "org/forgerock/openam/ui/common/SingleRouteRouter",
            // TODO: Remove this when there are no longer any references to the "underscore" dependency
            "underscore": "lodash"
        }
    },
    paths: {
        "lodash": "libs/lodash-3.10.1-min",
        "handlebars": "libs/handlebars-4.0.5",
        "i18next": "libs/i18next-1.7.3-min",
        "jquery": "libs/jquery-2.1.1-min",
        "text": "libs/text-2.0.15"
    },
    shim: {
        "handlebars": {
            exports: "handlebars"
        },
        "i18next": {
            deps: ["jquery", "handlebars"],
            exports: "i18n"
        },
        "lodash": {
            exports: "_"
        }
    }
});

require([
    "jquery",
    "lodash",
    "handlebars",
    "org/forgerock/commons/ui/common/main/Configuration",
    "org/forgerock/openam/ui/common/util/Constants",
    "text!templates/user/SAML2ConsentTemplate.html",
    "text!templates/common/LoginBaseTemplate.html",
    "text!templates/common/FooterTemplate.html",
    "text!templates/common/LoginHeaderTemplate.html",
    "org/forgerock/commons/ui/common/main/i18nManager",
    "ThemeManager",
    "Router",
    "org/forgerock/openam/ui/user/saml2/SAML2ConsentPageHelper",
    "org/forgerock/commons/ui/common/util/URIUtils"
], function ($, _, HandleBars, Configuration, Constants, SAML2ConsentTemplate,
    LoginBaseTemplate, FooterTemplate, LoginHeaderTemplate, i18nManager, ThemeManager, Router,
    SAML2ConsentPageHelper, URIUtils) {
    var data = {};

    const queryParams = URIUtils.parseQueryString(URIUtils.getCurrentCompositeQueryString());

    data.realm = queryParams.realm;
    data.spEntityId = queryParams.spEntityId;
    data.idpEntityId = queryParams.idpEntityId;
    data.originalRequestURI = queryParams.originalRequestURI;
    data.consentID = queryParams.consentID;
    data.forceConsent = queryParams.forceConsent;

    const template = SAML2ConsentTemplate;

    i18nManager.init({
        paramLang: {
            locale: data.locale
        },
        defaultLang: Constants.DEFAULT_LANGUAGE,
        nameSpace: "saml2consent"
    });

    Configuration.globalData = { realm: data.realm };
    Router.currentRoute = {
        navGroup: "user"
    };

    const agree = () => {
        const consentType = $('input[name="type"]:checked').val();
        const agreedAttributes = _.map(data.attributes, (attribute) => attribute.attributeName);

        SAML2ConsentPageHelper.agree(
            data.realm,
            data.consentID,
            agreedAttributes,
            consentType)
            .done(() => {
                // prevent open redirects
                if (SAML2ConsentPageHelper.isSameContextPath(data.originalRequestURI)) {
                    SAML2ConsentPageHelper.returnToSAMLFlow(data.originalRequestURI, data.consentID);
                } else {
                    data.error = "Invalid redirect URI.";
                    $("#content").html(HandleBars.compile(template)(data));
                }
            })
            .fail(() => {
                data.error = "Can't agree attributes.";
                $("#content").html(HandleBars.compile(template)(data));
            });
        return false;
    };

    const reject = () => {
        const rejectedAttributes = _.map(data.attributes, (attribute) => attribute.attributeName);

        SAML2ConsentPageHelper.reject(
            data.realm,
            data.consentID,
            rejectedAttributes)
            .done(() => {
                data.reject = true;
                $("#content").html(HandleBars.compile(template)(data));
            }).fail(() => {
                data.error = "Can't reject.";
                $("#content").html(HandleBars.compile(template)(data));
            });
        return false;
    };

    const fetchConsentRequiredAttrbutes = () => SAML2ConsentPageHelper
        .getConsentRequiredAttribute(
            data.realm,
            data.consentID,
            data.forceConsent)
        .done((consentRequiredAttributes) => { data.attributes = consentRequiredAttributes; })
        .fail(() => { data.error = "Can't fetch data."; });

    const fetchUIInfo = () => SAML2ConsentPageHelper
        .collectUIInfo(data.realm, data.spEntityId)
        .done((uiinfo) => { data = _.merge(data, uiinfo); })
        .fail(() => { data.error = "Can't fetch data."; });

    const fetchTheme = () => ThemeManager
        .getTheme()
        .done((theme) => { data.theme = theme; })
        .fail(() => { data.error = "Can't fetch theme."; });

    const render = () => {
        $("#wrapper").html(HandleBars.compile(LoginBaseTemplate)(data));
        $("#footer").html(HandleBars.compile(FooterTemplate)(data));
        $("#loginBaseLogo").html(HandleBars.compile(LoginHeaderTemplate)(data));
        $("#content").html(HandleBars.compile(template)(data));

        $("#agree").bind("click", agree);
        $("#reject").bind("click", reject);
    };

    const fetchData = () => $.when(
        fetchConsentRequiredAttrbutes(),
        fetchUIInfo(),
        fetchTheme()
    );

    if (data.forceConsent === "true") {
        fetchData().always(render);
    } else {
        fetchData()
            .done(() => {
                if (data.attributes.length === 0) {
                    agree();
                } else {
                    render();
                }
            })
            .fail(render);
    }
});
