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
import { RadioInputGroup } from "../Components/RadioInputGroup"
import { CheckboxInput } from "../Components/CheckboxInput";
import { Grid, Card, CardContent } from "@mui/material";
import { TextInput } from "../Components/TextInput";
import { PasswordInput } from "../Components/PasswordInput";
import { postData } from "../utils/postData";
import { useEffect } from "react";

const Step4 = () => {
    const USE_EXTERNAL_USER_STORE = "USE_EXTERNAL_USER_STORE";
    const USER_STORE_SSL = "USER_STORE_SSL";

    const { watch, formState, trigger, setValue } = useFormContext();

    const validateUserStore = async () => {
        await Promise.all([
            trigger(SetupConstants.USER_STORE_PORT),
            trigger(SetupConstants.USER_STORE_LOGIN_ID),
            trigger(SetupConstants.USER_STORE_ROOT_SUFFIX),
            trigger(SetupConstants.USER_STORE_LOGIN_PWD)
        ]);
        console.log(formState.errors);
        if (
            formState.errors[SetupConstants.USER_STORE_PORT] ||
            formState.errors[SetupConstants.USER_STORE_LOGIN_ID] ||
            formState.errors[SetupConstants.USER_STORE_ROOT_SUFFIX] ||
            formState.errors[SetupConstants.USER_STORE_LOGIN_PWD]
        ) {
            return true;
        }
        const endpoint = "./validate";
        const data = {
            type: "ldapConnection",
            dstype: watch(SetupConstants.USER_STORE_TYPE) === SetupConstants.UM_LDAPv3ForADDC ? "AD" : null,
            ssl: watch(USER_STORE_SSL) ? "SSL" : "SIMPLE",
            host: watch(SetupConstants.USER_STORE_HOST),
            domainName: watch(SetupConstants.USER_STORE_DOMAINNAME),
            port: watch(SetupConstants.USER_STORE_PORT),
            bindDN: watch(SetupConstants.USER_STORE_LOGIN_ID),
            rootSuffix: watch(SetupConstants.USER_STORE_ROOT_SUFFIX),
            password: watch(SetupConstants.USER_STORE_LOGIN_PWD)
        };
        const response = await postData(endpoint, data);
        const result = await response.json();
        if (data.dstype === "AD" && !result.error) {
            setValue(SetupConstants.USER_STORE_HOST, result.host);
            setValue(SetupConstants.USER_STORE_PORT, result.port);
            setValue(SetupConstants.USER_STORE_ROOT_SUFFIX, result.rootSuffix);
        }
        return result.error ? t(result.error.code) : true;
    }

    const validateRootSuffix = async (rootSuffix) => {
        const endpoint = "./validate";
        const response = await postData(endpoint, { type: "rootSuffix", rootSuffix: rootSuffix });
        const result = await response.json();
        return result.error ? t(result.error.code) : true;
    }

    useEffect(() => {
        if (watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_DS_DATASTORE) {
            setValue(USE_EXTERNAL_USER_STORE, "true");
        }
    }, []);

    const { t } = useTranslation();

    return (
        <div id="wizardStep4">
            <h1>{t("step4.title")}</h1>
            <p>{t("step4.description")}</p>
            <RadioInputGroup
                name={USE_EXTERNAL_USER_STORE}
                choices={[
                    { label: t("options.userStore.embedded"), value: "false" },
                    { label: t("options.userStore.external"), value: "true" }
                ]}
                readOnly={watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_DS_DATASTORE}
            ></RadioInputGroup>
            {watch(USE_EXTERNAL_USER_STORE) === "false" &&
                <>
                    <p>{t("step4.message.embeddedUserStore")}</p>
                </>
            }
            {watch(USE_EXTERNAL_USER_STORE) === "true" &&
                <Card variant="outlined" sx={{ height: "60vh", overflowY: "auto" }}>
                    <CardContent>
                        <h3>{t("step4.subtitle")}</h3>
                        <Card variant="outlined" >
                            <CardContent>
                                <p>{t("label.userStoreType")}</p>
                                <RadioInputGroup
                                    name={SetupConstants.USER_STORE_TYPE}
                                    choices={[
                                        { label: t("label.storeType.opendj"), value: SetupConstants.UM_LDAPv3ForOpenDS },
                                        { label: t("label.storeType.ADDC"), value: SetupConstants.UM_LDAPv3ForADDC },
                                        { label: t("label.storeType.tivoli"), value: SetupConstants.UM_LDAPv3ForTivoli },
                                        { label: t("label.storeType.ODSEE"), value: SetupConstants.UM_LDAPv3ForODSEE },
                                        { label: t("label.storeType.ADWithHostAndPort"), value: SetupConstants.UM_LDAPv3ForAD },
                                        { label: t("label.storeType.ADAM"), value: SetupConstants.UM_LDAPv3ForADAM }
                                    ]}></RadioInputGroup>
                            </CardContent>
                        </Card>
                        <CheckboxInput
                            label={t("label.sslEnabled")}
                            name={USER_STORE_SSL}
                        ></CheckboxInput>
                        <Grid container spacing={2}>
                            {watch(SetupConstants.USER_STORE_TYPE) === SetupConstants.UM_LDAPv3ForADDC &&
                                <Grid size={{ md: 12 }}>
                                    <TextInput
                                        label={t("label.domainName")}
                                        name={SetupConstants.USER_STORE_DOMAINNAME}
                                        rules={{
                                            required: t("error.missingDomainName"),
                                            validate: validateUserStore
                                        }}
                                    ></TextInput>
                                </Grid>
                            }
                            {watch(SetupConstants.USER_STORE_TYPE) !== SetupConstants.UM_LDAPv3ForADDC &&
                                <>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            label={t("label.directoryName")}
                                            name={SetupConstants.USER_STORE_HOST}
                                            rules={{
                                                required: t("error.missingHostname"),
                                                validate: validateUserStore
                                            }}
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            label={t("label.port")}
                                            name={SetupConstants.USER_STORE_PORT}
                                            rules={{
                                                required: t("error.missingPort"),
                                                pattern: {
                                                    value: /^[0-9]*$/,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                min: {
                                                    value: 1,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                max: {
                                                    value: 65535,
                                                    message: t("error.invalidPortNumber")
                                                }
                                            }}
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            label={t("label.rootSuffix")}
                                            name={SetupConstants.USER_STORE_ROOT_SUFFIX}
                                            rules={{
                                                required: t("error.missingRequiredField"),
                                                validate: validateRootSuffix
                                            }}
                                        ></TextInput>
                                    </Grid>
                                </>
                            }
                            <Grid size={{ md: 12 }}>
                                <TextInput
                                    label={t("label.loginID")}
                                    name={SetupConstants.USER_STORE_LOGIN_ID}
                                    rules={{ required: t("error.missingLoginID") }}
                                ></TextInput>
                            </Grid>
                            <Grid size={{ md: 12 }}>
                                <PasswordInput
                                    label={t("label.password")}
                                    name={SetupConstants.USER_STORE_LOGIN_PWD}
                                    rules={{ required: t("error.missingPassword") }}
                                ></PasswordInput>
                            </Grid>
                        </Grid>
                    </CardContent>
                </Card>
            }
        </div>
    )
}

export default Step4;
