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
import { useTranslation } from "react-i18next";
import { RadioInputGroup } from "../Components/RadioInputGroup";
import { TextInput } from "../Components/TextInput";
import { CheckboxInput } from "../Components/CheckboxInput";
import { Card, CardContent, Grid } from "@mui/material";

const Step5 = () => {
    const BEHIND_LB = "BEHIND_LB";

    const { watch } = useFormContext();
    const { t } = useTranslation();

    const validatePrimaryURL = async (urlStr) => {
        try {
            const url = new URL(urlStr);
            if (!url.host) {
                return t("error.missingHostname");
            }
            if (!url.pathname.slice(1)) {
                return t("primary.url.no.uri");
            }
            return true;
        } catch (e) {
            return t("error.invalidPrimaryURL");
        }
    }

    return (
        <div id="wizardStep5">
            <h1>{t("step5.title")}</h1>
            <p>{t("step5.description")}</p>
            <RadioInputGroup
                name={BEHIND_LB}
                choices={[
                    { label: t("label.no"), value: "false" },
                    { label: t("label.yes"), value: "true" }
                ]}
            ></RadioInputGroup>
            {watch(BEHIND_LB) === "true" &&
                <Card variant="outlined">
                    <CardContent>
                        <p>{t("step5.message.help")}</p>
                        <Grid container spacing={2}>
                            <Grid size={{ md: 12 }}>
                                <TextInput
                                    label={t("label.siteName")}
                                    name={SetupConstants.LB_SITE_NAME}
                                    rules={{
                                        required: t("error.missingSiteName")
                                    }}
                                ></TextInput>
                            </Grid>
                            <Grid size={{ md: 12 }}>
                                <TextInput
                                    label={t("label.primaryURL")}
                                    name={SetupConstants.LB_PRIMARY_URL}
                                    rules={{
                                        required: t("error.missingPrimaryURL"),
                                        validate: validatePrimaryURL
                                    }}></TextInput>
                            </Grid>
                            <Grid size={{ md: 12 }}>
                                <CheckboxInput
                                    label={t("label.enableSessionFailOver")}
                                    name={SetupConstants.LB_SESSION_HA_SFO}
                                ></CheckboxInput>
                            </Grid>
                        </Grid>
                    </CardContent>
                </Card>
            }
        </div>
    )
}

export default Step5;
