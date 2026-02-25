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

import { useFormContext } from "react-hook-form";
import { SetupConstants } from "../SetupConstants";
import { postData } from "../utils/postData";
import { useTranslation } from "react-i18next";
import { TextInput } from "../Components/TextInput";
import { Card, CardContent, Grid } from "@mui/material";

const Step2 = () => {
    const { watch, trigger } = useFormContext()
    const { t } = useTranslation();

    const validateDirectory = async (path) => {
        const endpoint = "./validate";
        const response = await postData(endpoint, { type: "configDirectory", dir: path });
        const result = await response.json();
        return result.error ? t(result.error.code) : true;
    }

    const validateCookieDomain = (cookieDomain) => {
        if (!cookieDomain) {
            return true;
        }
        if (cookieDomain.includes(":") || cookieDomain.startsWith(".")) {
            return t("error.invalidCookieDomain");
        }
        try {
            const url = new URL(watch(SetupConstants.CONFIG_VAR_SERVER_URL));
            if (!url.hostname.endsWith(cookieDomain)) {
                return t("error.mismatchedCookieDomain");
            }
            return true;
        } catch (e) {
            return t("error.mismatchedCookieDomain");
        }
    }

    return (
        <div id="wizardStep2">
            <h1>{t("step2.title")}</h1>
            <p>{t("step2.description")}</p>
            <Card variant="outlined">
                <CardContent>
                    <h3>{t("step2.subtitle")}</h3>
                    <Grid container spacing={2}>
                        <Grid size={{ md: 12 }}>
                            <TextInput
                                name={SetupConstants.CONFIG_VAR_SERVER_URL}
                                label={t("label.serverURL")}
                                rules={{
                                    required: t("error.missingRequiredField"),
                                    validate: () => { trigger(SetupConstants.CONFIG_VAR_COOKIE_DOMAIN); return true }
                                }}></TextInput>
                        </Grid>
                        <Grid size={{ md: 12 }}>
                            <TextInput
                                name={SetupConstants.CONFIG_VAR_COOKIE_DOMAIN}
                                label={t("label.cookieDomain")}
                                rules={{
                                    validate: validateCookieDomain
                                }}></TextInput>
                        </Grid>
                        <Grid size={{ md: 12 }}>
                            <TextInput
                                name={SetupConstants.CONFIG_VAR_PLATFORM_LOCALE}
                                label={t("label.platformLocale")}
                                rules={{
                                    required: t("error.missingRequiredField")
                                }}></TextInput>
                        </Grid>
                        <Grid size={{ md: 12 }}>
                            <TextInput
                                name={SetupConstants.CONFIG_VAR_BASE_DIR}
                                label={t("label.configDirectoy")}
                                rules={{
                                    required: t("error.missingRequiredField"),
                                    validate: validateDirectory
                                }}></TextInput>
                        </Grid>
                    </Grid>
                </CardContent>
            </Card>
        </div>
    )
}

export default Step2;
