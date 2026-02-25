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
import { RadioInputGroup } from "../Components/RadioInputGroup";
import { useTranslation } from "react-i18next";
import { Card, CardContent, Grid } from "@mui/material";
import { CheckboxInput } from "../Components/CheckboxInput";
import { TextInput } from "../Components/TextInput";
import { PasswordInput } from "../Components/PasswordInput";
import { useEffect, useState } from "react";

const Step3 = () => {
    const SSL_ENABLED = "SSL_ENABLED";
    const [remoteServerInfo, setRemoteServerInfo] = useState({});
    const { watch, setValue, trigger, formState } = useFormContext();

    const useEmbeddedDatastore
        = watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_EMBED_DATASTORE;
    useEffect(() => {
        if (useEmbeddedDatastore) {
            setValue(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_HOST, "localhost");
            setValue(SSL_ENABLED, false);
        }
    }, [useEmbeddedDatastore, setValue])

    const { t } = useTranslation();

    const validateHost = async (hostName) => {
        if (useEmbeddedDatastore) {
            return true;
        }
        const endpoint = "./validate";
        const hostnameResponse = await postData(endpoint, { type: "configStoreHost", host: hostName });
        const hostnameResult = await hostnameResponse.json();
        if (hostnameResult.error) {
            return t(hostnameResult.error.code);
        }
        await Promise.all([
            trigger(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT),
            trigger(SetupConstants.CONFIG_VAR_DS_MGR_DN),
            trigger(SetupConstants.CONFIG_VAR_ROOT_SUFFIX),
            trigger(SetupConstants.CONFIG_VAR_DS_MGR_PWD)
        ]);
        if (
            formState.errors[SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT] ||
            formState.errors[SetupConstants.CONFIG_VAR_DS_MGR_DN] ||
            formState.errors[SetupConstants.CONFIG_VAR_ROOT_SUFFIX] ||
            formState.errors[SetupConstants.CONFIG_VAR_DS_MGR_PWD]
        ) {
            return true;
        }
        const ldapConnectionData = {
            type: "ldapConnection",
            ssl: watch(SSL_ENABLED),
            host: hostName,
            port: watch(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT),
            bindDN: watch(SetupConstants.CONFIG_VAR_DS_MGR_DN),
            rootSuffix: watch(SetupConstants.CONFIG_VAR_ROOT_SUFFIX),
            password: watch(SetupConstants.CONFIG_VAR_DS_MGR_PWD)
        };
        const ldapConnectionResponse = await postData(endpoint, ldapConnectionData);
        const ldapConnectionResult = await ldapConnectionResponse.json();
        return ldapConnectionResult.error ? t(ldapConnectionResult.error.code) : true;
    }
    const validatePort = async (port) => {
        if (watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_DS_DATASTORE) {
            return true;
        }
        const endpoint = "./validate";
        const response = await postData(endpoint, { type: "localPort", port: port });
        const result = await response.json();
        return result.error ? t(result.error.code) : true;
    }
    const validateRootSuffix = async (rootSuffix) => {
        const endpoint = "./validate";
        const response = await postData(endpoint, { type: "rootSuffix", rootSuffix: rootSuffix });
        const result = await response.json();
        return result.error ? t(result.error.code) : true;
    }

    const getRemoteServerInfo = async (serverURL) => {
        const password = watch(SetupConstants.CONFIG_VAR_ADMIN_PWD);
        const endpoint = "./validate";
        const data = { type: "remoteServer", host: serverURL, password: password };
        const response = await postData(endpoint, data);
        const result = await response.json();
        if (!result.error) {
            setRemoteServerInfo(result);
        } else {
            setRemoteServerInfo({});
        }
        return result.error ? t(result.error.code) : true;
    }

    useEffect(() => {
        if (Object.keys(remoteServerInfo).length > 0) {
            setValue(SetupConstants.CONFIG_VAR_ENCRYPTION_KEY, remoteServerInfo.enckey);
            setValue(SetupConstants.CONFIG_VAR_ROOT_SUFFIX, remoteServerInfo.dsbasedn);
            setValue(SetupConstants.ENCRYPTED_LDAP_USER_PWD, remoteServerInfo[SetupConstants.ENCRYPTED_LDAP_USER_PWD]);
            const embedded = remoteServerInfo.dsisembedded === "true";
            if (embedded) {
                setValue(SetupConstants.CONFIG_VAR_DATA_STORE, SetupConstants.SMS_EMBED_DATASTORE);
                setValue(SetupConstants.DS_EMB_REPL_REPLPORT2, remoteServerInfo.dsreplport);
                setValue(SetupConstants.DS_EMB_EXISTING_SERVERID, remoteServerInfo.existingserverid);
                setValue(SetupConstants.CONFIG_VAR_DS_MGR_PWD, watch(SetupConstants.CONFIG_VAR_ADMIN_PWD));
            } else {
                setValue(SetupConstants.CONFIG_VAR_DATA_STORE, SetupConstants.SMS_DS_DATASTORE);
                setValue(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_HOST, remoteServerInfo.dshost);
                setValue(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT, remoteServerInfo.dsport);
                const SSL = remoteServerInfo.dsprotocol === "ldaps" ? "SSL" : "SIMPLE";
                setValue(SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_SSL, SSL);
                setValue(SetupConstants.CONFIG_VAR_DS_MGR_PWD, remoteServerInfo[SetupConstants.CONFIG_VAR_DS_MGR_PWD]);
            }
            setValue(SetupConstants.DS_EMB_REPL_ADMINPORT2, remoteServerInfo[SetupConstants.DS_EMB_REPL_ADMINPORT2]);
        }
    }, [remoteServerInfo.existingserverid])

    return (
        <div id="wizardStep3">
            <h1>{t("step3.title")}</h1>
            <p>{t("step3.description")}</p>
            <RadioInputGroup
                name={SetupConstants.DS_EMB_REPL_FLAG}
                choices={[
                    { label: t("options.instance.createNewInstance"), value: "" },
                    { label: t("options.instance.addToExistingInstance"), value: SetupConstants.DS_EMP_REPL_FLAG_VAL }
                ]}
            ></RadioInputGroup>
            <Card variant="outlined" sx={{ maxHeight: "60vh", overflowY: "auto" }}>
                <CardContent>
                    {watch(SetupConstants.DS_EMB_REPL_FLAG) === "" &&
                        <>
                            <h3>{t("step3.subtitle")}</h3>
                            <Card variant="outlined">
                                <CardContent>
                                    <p>{t("label.configStore")}</p>
                                    <RadioInputGroup
                                        name={SetupConstants.CONFIG_VAR_DATA_STORE}
                                        choices={[
                                            { label: t("options.configStore.embedded"), value: SetupConstants.SMS_EMBED_DATASTORE },
                                            { label: t("options.configStore.external"), value: SetupConstants.SMS_DS_DATASTORE }
                                        ]}></RadioInputGroup>
                                </CardContent>
                            </Card>
                        </>}
                    {watch(SetupConstants.DS_EMB_REPL_FLAG) === "" &&
                        <Grid container spacing={2}>
                            <Grid size={{ md: 12 }}>
                                <CheckboxInput
                                    label={t("label.sslEnabled")}
                                    name={SSL_ENABLED}
                                    disabled={watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_EMBED_DATASTORE}></CheckboxInput>
                            </Grid>
                            <Grid size={{ md: 12 }}>
                                <TextInput
                                    name={SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_HOST}
                                    label={t("label.hostname")}
                                    readOnly={watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_EMBED_DATASTORE}
                                    rules={{
                                        required: t("error.missingRequiredField"),
                                        validate: validateHost
                                    }}
                                ></TextInput>
                            </Grid>
                            <Grid size={{ md: 12 }}>
                                <TextInput
                                    name={SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT}
                                    label={t("label.port")}
                                    rules={{
                                        required: t("error.missingRequiredField"),
                                        min: {
                                            value: 1,
                                            message: t("error.invalidPortNumber")
                                        },
                                        max: {
                                            value: 65535,
                                            message: t("error.invalidPortNumber")
                                        },
                                        validate: validatePort
                                    }}
                                ></TextInput>
                            </Grid>

                            {watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_EMBED_DATASTORE &&
                                <>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.CONFIG_VAR_DIRECTORY_ADMIN_SERVER_PORT}
                                            label={t("label.adminPort")}
                                            rules={{
                                                required: t("error.missingRequiredField"),
                                                min: {
                                                    value: 1,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                max: {
                                                    value: 65535,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                validate: validatePort
                                            }}
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.CONFIG_VAR_DIRECTORY_JMX_SERVER_PORT}
                                            label={t("label.jmxPort")}
                                            rules={{
                                                required: t("error.missingRequiredField"),
                                                min: {
                                                    value: 1,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                max: {
                                                    value: 65535,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                validate: validatePort
                                            }}
                                        ></TextInput>
                                    </Grid>
                                </>}
                            <Grid size={{ md: 12 }}>
                                <TextInput
                                    name={SetupConstants.CONFIG_VAR_ENCRYPTION_KEY}
                                    label={t("label.encKey")}
                                    rules={{
                                        required: t("error.missingRequiredField"),
                                        minLength: {
                                            value: 10,
                                            message: t("error.encKeyNeed10Chars")
                                        }
                                    }}
                                ></TextInput>
                            </Grid>
                            <Grid size={{ md: 12 }}>
                                <TextInput
                                    name={SetupConstants.CONFIG_VAR_ROOT_SUFFIX}
                                    label={t("label.rootSuffix")}
                                    rules={{
                                        required: t("error.missingRequiredField"),
                                        validate: validateRootSuffix
                                    }}
                                ></TextInput>
                            </Grid>
                            {watch(SetupConstants.CONFIG_VAR_DATA_STORE) === SetupConstants.SMS_DS_DATASTORE &&
                                <>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.CONFIG_VAR_DS_MGR_DN}
                                            label={t("label.loginID")}
                                            rules={{
                                                required: t("error.missingRequiredField")
                                            }}
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <PasswordInput
                                            name={SetupConstants.CONFIG_VAR_DS_MGR_PWD}
                                            label={t("label.password")}
                                            rules={{
                                                required: t("error.missingRequiredField")
                                            }}></PasswordInput>
                                    </Grid>
                                </>}
                        </Grid>
                    }

                    {watch(SetupConstants.DS_EMB_REPL_FLAG) === SetupConstants.DS_EMP_REPL_FLAG_VAL &&
                        <Grid container spacing={2}>
                            <Grid size={{ md: 12 }}>
                                <TextInput
                                    name={SetupConstants.DS_EMB_REPL_HOST2}
                                    label={t("label.serverURL")}
                                    rules={{
                                        required: t("error.missingRequiredField"),
                                        validate: getRemoteServerInfo
                                    }}
                                ></TextInput>
                            </Grid>
                            {Object.keys(remoteServerInfo).length > 0 && remoteServerInfo.dsisembedded === "true" &&
                                <>
                                    <h4>{t("step3.localPorts")}</h4>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT}
                                            label={t("label.localReplicationPort")}
                                            rules={{
                                                required: t("error.missingRequiredField"),
                                                min: {
                                                    value: 1,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                max: {
                                                    value: 65535,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                validate: validatePort
                                            }}
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.CONFIG_VAR_DIRECTORY_ADMIN_SERVER_PORT}
                                            label={t("label.adminPort")}
                                            rules={{
                                                required: t("error.missingRequiredField"),
                                                min: {
                                                    value: 1,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                max: {
                                                    value: 65535,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                validate: validatePort
                                            }}
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.DS_EMB_REPL_REPLPORT1}
                                            label={t("label.replicationPort")}
                                            rules={{
                                                required: t("error.missingRequiredField"),
                                                min: {
                                                    value: 1,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                max: {
                                                    value: 65535,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                validate: validatePort
                                            }}
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.CONFIG_VAR_DIRECTORY_JMX_SERVER_PORT}
                                            label={t("label.jmxPort")}
                                            rules={{
                                                required: t("error.missingRequiredField"),
                                                min: {
                                                    value: 1,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                max: {
                                                    value: 65535,
                                                    message: t("error.invalidPortNumber")
                                                },
                                                validate: validatePort
                                            }}
                                        ></TextInput>
                                    </Grid>
                                    <h4>{t("step3.remotePorts")}</h4>
                                    {remoteServerInfo.dsreplportavailable === "true"
                                        ? <p>{t("step3.message.replication")}</p>
                                        : <p>{t("step3.message.noreplication")}</p>
                                    }
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.DS_EMB_REPL_ADMINPORT2}
                                            label={t("label.remoteAdminPort")}
                                            rules={{
                                                required: t("error.missingRequiredField")
                                            }}
                                            readOnly
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.DS_EMB_REPL_REPLPORT2}
                                            label={t("label.remoteReplicationPort")}
                                            rules={{
                                                required: t("error.missingRequiredField"),
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
                                            readOnly={remoteServerInfo.dsreplportavailable === "true"}
                                        ></TextInput>
                                    </Grid>
                                </>
                            }
                            {Object.keys(remoteServerInfo).length > 0 && remoteServerInfo.dsisembedded !== "true" &&
                                <>
                                    <h4>{t("step3.remotePorts")}</h4>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_HOST}
                                            label={t("label.hostname")}
                                            readOnly
                                        ></TextInput>
                                    </Grid>
                                    <Grid size={{ md: 12 }}>
                                        <TextInput
                                            name={SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT}
                                            label={t("label.port")}
                                            readOnly
                                        ></TextInput>
                                    </Grid>
                                </>
                            }
                        </Grid>
                    }
                </CardContent>
            </Card>
        </div>
    )
}

export default Step3;
