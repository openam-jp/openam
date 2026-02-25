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
import { useTranslation } from "react-i18next";
import { Button, Card, CardContent, Table, TableBody, TableCell, TableRow, Box } from "@mui/material";
import { SetupConstants } from "../SetupConstants";

const Step7 = ({ setStep }) => {
    const { watch } = useFormContext();
    const { t } = useTranslation();

    const configStoreSummary = {};
    configStoreSummary[t("label.sslEnabled")]
        = watch(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_SSL) === "SSL" ? t("label.yes") : t("label.no");
    configStoreSummary[t("label.hostname")] = watch(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_HOST);
    configStoreSummary[t("label.localReplicationPort")] = watch(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT);
    if (watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_EMBED_DATASTORE) {
        configStoreSummary[t("label.adminPort")] = watch(SetupConstants.CONFIG_VAR_DIRECTORY_ADMIN_SERVER_PORT);
        configStoreSummary[t("label.jmxPort")] = watch(SetupConstants.CONFIG_VAR_DIRECTORY_JMX_SERVER_PORT);
    }
    configStoreSummary[t("label.rootSuffix")] = watch(SetupConstants.CONFIG_VAR_ROOT_SUFFIX);
    configStoreSummary[t("step7.loginID")] = watch(SetupConstants.CONFIG_VAR_DS_MGR_DN);
    configStoreSummary[t("label.directoryName")] = watch(SetupConstants.CONFIG_VAR_BASE_DIR);

    const userStoreSummary = {};
    userStoreSummary[t("label.sslEnabled")]
        = watch(SetupConstants.USER_STORE_SSL) === "SSL" ? t("label.yes") : t("label.no");
    userStoreSummary[t("label.hostname")] = watch(SetupConstants.USER_STORE_HOST);
    userStoreSummary[t("label.localReplicationPort")] = watch(SetupConstants.USER_STORE_PORT);
    userStoreSummary[t("label.rootSuffix")] = watch(SetupConstants.USER_STORE_ROOT_SUFFIX);
    userStoreSummary[t("step7.loginID")] = watch(SetupConstants.USER_STORE_LOGIN_ID);
    userStoreSummary[t("label.userStoreType")] = watch(SetupConstants.USER_STORE_TYPE);

    const siteConfigSummary = {}
    siteConfigSummary[t("label.siteName")] = watch(SetupConstants.LB_SITE_NAME);
    siteConfigSummary[t("label.primaryURL")] = watch(SetupConstants.LB_PRIMARY_URL);
    siteConfigSummary[t("label.enableSessionFailOver")]
        = watch(SetupConstants.LB_SESSION_HA_SFO) ? t("label.yes") : t("label.no");

    return (
        <div id="wizardStep7">
            <h1>{t("step7.title")}</h1>
            <p>{t("step7.description")}</p>
            <Card variant="outlined" sx={{ maxHeight: "70vh", overflowY: "auto" }}>
                <CardContent>
                    <Box component="h3" sx={{ display: "inline-block" }}>{t("step3.subtitle")}</Box>
                    <Button color="primary" onClick={(() => setStep(2))}>{t("step7.edit")}</Button>
                    <Table size="small">
                        <TableBody>
                            {Object.keys(configStoreSummary).map(key => (
                                <TableRow key={key}>
                                    <TableCell>{key}</TableCell>
                                    <TableCell>{configStoreSummary[key]}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                    <Box component="h3" sx={{ display: "inline-block" }}>{t("step4.subtitle")}</Box>
                    <Button color="primary" onClick={(() => setStep(3))}>{t("step7.edit")}</Button>
                    <Table size="small">
                        <TableBody>
                            {watch("USE_EXTERNAL_USER_STORE") === "true" ? (
                                Object.keys(userStoreSummary).map(key => (
                                    <TableRow key={key}>
                                        <TableCell>{key}</TableCell>
                                        <TableCell>{userStoreSummary[key]}</TableCell>
                                    </TableRow>
                                ))) : (
                                <p>{t("step7.defaultUserStore")}</p>
                            )}
                        </TableBody>
                    </Table>
                    <Box component="h3" sx={{ display: "inline-block" }}>{t("step5.subtitle")}</Box>
                    <Button color="primary" onClick={(() => setStep(4))}>{t("step7.edit")}</Button>
                    <Table size="small">
                        {watch(SetupConstants.LB_SITE_NAME) ? (
                            Object.keys(siteConfigSummary).map(key => (
                                <TableRow key={key}>
                                    <TableCell>{key}</TableCell>
                                    <TableCell>{siteConfigSummary[key]}</TableCell>
                                </TableRow>
                            ))
                        ) : (
                            <p>{t("step7.noSite")}</p>
                        )}
                    </Table>
                </CardContent>
            </Card>
        </div>
    )
}

export default Step7;
