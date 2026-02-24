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
import { Card, CardContent, Grid } from "@mui/material";
import { PasswordInput } from "../Components/PasswordInput";

const Step6 = () => {
    const { watch, trigger }
        = useFormContext();
    const { t } = useTranslation();

    return (
        <div id="wizardStep6">
            <h1>{t("step6.title")}</h1>
            <p>{t("step6.description")}</p>
            <Card variant="outlined">
                <CardContent>
                    <h3>{t("step6.subtitle")}</h3>
                    <Grid container spacing={2}>
                        <Grid size={12}>
                            <PasswordInput
                                name={SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD}
                                label={t("label.password")}
                                rules={{
                                    required: t("error.missingRequiredField"),
                                    minLength: {
                                        value: 8,
                                        message: t("error.passwordSizeInvalid")
                                    },
                                    validate: {
                                        trigger: () => { trigger(SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD_CONFIRM); return true },
                                        samePassword: value => value !== watch(SetupConstants.CONFIG_VAR_ADMIN_PWD) || t("error.agentAdminPasswordSame")
                                    }
                                }}
                            ></PasswordInput>
                        </Grid>
                        <Grid size={12}>
                            <PasswordInput
                                name={SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD_CONFIRM}
                                label={t("label.passwordConfirm")}
                                rules={{
                                    required: t("error.missingRequiredField"),
                                    validate: (value) => value === watch(SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD) || t("error.passwordDontMatch")
                                }}
                            ></PasswordInput>
                        </Grid>
                    </Grid>
                </CardContent>
            </Card>
        </div>
    )
}

export default Step6;
