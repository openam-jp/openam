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

import { useState, useEffect } from 'react';
import Step1 from './Step1';
import Step2 from './Step2';
import Step3 from './Step3';
import Step4 from './Step4';
import Step5 from './Step5';
import Step6 from './Step6';
import Step7 from './Step7';
import React from 'react';
import { SetupConstants } from '../SetupConstants';
import { Button, Card, CardActions, CardContent, Container, Grid } from '@mui/material';
import { CustomSettingStepper } from "../Components/CustomSettingStepper"
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { FormProvider, useForm } from 'react-hook-form';
import { InstallDialog } from '../Components/InstallDialog';
import { postData } from '../utils/postData';

const CustomSetting = () => {
    const methods = useForm({ mode: "onChange" });
    const [step, setStep] = useState(0);
    const [installing, setInstalling] = useState(false);
    const [installComplete, setInstallComplete] = useState(false);
    const [installErrorMessage, setInstallErrorMessage] = useState("");
    const forms = [Step1, Step2, Step3, Step4, Step5, Step6, Step7];
    const navigate = useNavigate();
    const { t } = useTranslation();

    useEffect(() => {
        const getDefaultValues = async () => {
            const defaultValueURL = "./defaultValues";
            const response = await fetch(defaultValueURL, {
                method: "GET",
                credentials: "same-origin"
            });
            const defaultValues = await response.json();
            for (const key in defaultValues) {
                methods.setValue(key, defaultValues[key]);
            }
            methods.setValue(SetupConstants.ACCEPT_LICENSE_PARAM, true);
            methods.setValue(SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD, "");
            methods.setValue(SetupConstants.USER_STORE_TYPE, SetupConstants.UM_LDAPv3ForOpenDS);
            methods.setValue("USE_EXTERNAL_USER_STORE", "false");
            methods.setValue("BEHIND_LB", "false");
        }
        getDefaultValues();
    }, []);

    const incrementStep = () => {
        if (methods.watch(SetupConstants.DS_EMB_REPL_FLAG) === SetupConstants.DS_EMP_REPL_FLAG_VAL) {
            if (step === 2 || step === 4) {
                setStep(step + 2);
            } else (
                setStep(step + 1)
            )
        } else {
            setStep(step + 1);
        }
    }
    const decrementStep = () => {
        if (methods.watch(SetupConstants.DS_EMB_REPL_FLAG) === SetupConstants.DS_EMP_REPL_FLAG_VAL) {
            if (step === 6 || step === 4) {
                setStep(step - 2);
            } else {
                setStep(step - 1)
            }
        } else {
            setStep(step - 1);
        }
    }

    const submitData = async (data) => {
        if (data["USE_EXTERNAL_USER_STORE"] === "true") {
            data[SetupConstants.USER_STORE] = "true";
        }
        if (data["BEHIND_LB"] === "false") {
            data[SetupConstants.LB_SITE_NAME] = "";
        }
        data[SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_SSL]
            = data["SSL_ENABLED"] ? "SSL" : "SIMPLE";
        data[SetupConstants.USER_STORE_SSL]
            = data["USER_STORE_SSL"] ? "SSL" : "SIMPLE";

        const submit = {};
        submit[SetupConstants.ACCEPT_LICENSE_PARAM] = data[SetupConstants.ACCEPT_LICENSE_PARAM];

        submit[SetupConstants.CONFIG_VAR_ADMIN_PWD] = data[SetupConstants.CONFIG_VAR_ADMIN_PWD];
        submit[SetupConstants.CONFIG_VAR_CONFIRM_ADMIN_PWD] = data[SetupConstants.CONFIG_VAR_CONFIRM_ADMIN_PWD];

        submit[SetupConstants.CONFIG_VAR_SERVER_URL] = data[SetupConstants.CONFIG_VAR_SERVER_URL];
        submit[SetupConstants.CONFIG_VAR_COOKIE_DOMAIN] = data[SetupConstants.CONFIG_VAR_COOKIE_DOMAIN];
        submit[SetupConstants.CONFIG_VAR_PLATFORM_LOCALE] = data[SetupConstants.CONFIG_VAR_PLATFORM_LOCALE];
        submit[SetupConstants.CONFIG_VAR_BASE_DIR] = data[SetupConstants.CONFIG_VAR_BASE_DIR];

        submit[SetupConstants.DS_EMB_REPL_FLAG] = data[SetupConstants.DS_EMB_REPL_FLAG];
        submit[SetupConstants.CONFIG_VAR_DATA_STORE] = data[SetupConstants.CONFIG_VAR_DATA_STORE];
        submit[SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_SSL] = data[SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_SSL];
        submit[SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_HOST] = data[SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_HOST];
        submit[SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT] = data[SetupConstants.CONFIG_VAR_DIRECTORY_SERVER_PORT];
        submit[SetupConstants.CONFIG_VAR_ENCRYPTION_KEY] = data[SetupConstants.CONFIG_VAR_ENCRYPTION_KEY];
        submit[SetupConstants.CONFIG_VAR_ROOT_SUFFIX] = data[SetupConstants.CONFIG_VAR_ROOT_SUFFIX];

        if (data[SetupConstants.CONFIG_VAR_DATA_STORE] === SetupConstants.SMS_EMBED_DATASTORE) {
            submit[SetupConstants.CONFIG_VAR_DIRECTORY_ADMIN_SERVER_PORT] = data[SetupConstants.CONFIG_VAR_DIRECTORY_ADMIN_SERVER_PORT];
            submit[SetupConstants.CONFIG_VAR_DIRECTORY_JMX_SERVER_PORT] = data[SetupConstants.CONFIG_VAR_DIRECTORY_JMX_SERVER_PORT];
        } else {
            submit[SetupConstants.CONFIG_VAR_DS_MGR_DN] = data[SetupConstants.CONFIG_VAR_DS_MGR_DN];
            submit[SetupConstants.CONFIG_VAR_DS_MGR_PWD] = data[SetupConstants.CONFIG_VAR_DS_MGR_PWD];
        }

        if (data[SetupConstants.DS_EMB_REPL_FLAG] === SetupConstants.DS_EMP_REPL_FLAG_VAL) {
            submit[SetupConstants.DS_EMB_EXISTING_SERVERID] = data[SetupConstants.DS_EMB_EXISTING_SERVERID];
            submit[SetupConstants.ENCRYPTED_LDAP_USER_PWD] = data[SetupConstants.ENCRYPTED_LDAP_USER_PWD];
            submit[SetupConstants.DS_EMB_REPL_HOST2] = data[SetupConstants.DS_EMB_REPL_HOST2];
            submit[SetupConstants.DS_EMB_REPL_REPLPORT1] = data[SetupConstants.DS_EMB_REPL_REPLPORT1];
            submit[SetupConstants.DS_EMB_REPL_REPLPORT2] = data[SetupConstants.DS_EMB_REPL_REPLPORT2];
            submit[SetupConstants.DS_EMB_REPL_ADMINPORT2] = data[SetupConstants.DS_EMB_REPL_ADMINPORT2];
        } else {
            submit[SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD] = data[SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD];
            submit[SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD_CONFIRM] = data[SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD_CONFIRM];

            submit[SetupConstants.USER_STORE] = data[SetupConstants.USER_STORE];
            if (data[SetupConstants.USER_STORE] === "true") {
                submit[SetupConstants.USER_STORE_TYPE] = data[SetupConstants.USER_STORE_TYPE];
                submit[SetupConstants.USER_STORE_SSL] = data[SetupConstants.USER_STORE_SSL];
                submit[SetupConstants.USER_STORE_LOGIN_ID] = data[SetupConstants.USER_STORE_LOGIN_ID];
                submit[SetupConstants.USER_STORE_LOGIN_PWD] = data[SetupConstants.USER_STORE_LOGIN_PWD];
                submit[SetupConstants.USER_STORE_HOST] = data[SetupConstants.USER_STORE_HOST];
                submit[SetupConstants.USER_STORE_PORT] = data[SetupConstants.USER_STORE_PORT];
                submit[SetupConstants.USER_STORE_ROOT_SUFFIX] = data[SetupConstants.USER_STORE_ROOT_SUFFIX];
                if (data[SetupConstants.USER_STORE_TYPE] === SetupConstants.UM_LDAPv3ForADDC) {
                    submit[SetupConstants.USER_STORE_DOMAINNAME] = data[SetupConstants.USER_STORE_DOMAINNAME];
                }
            }
        }
        if (data[SetupConstants.LB_SITE_NAME]) {
            submit[SetupConstants.LB_SITE_NAME] = data[SetupConstants.LB_SITE_NAME];
            submit[SetupConstants.LB_PRIMARY_URL] = data[SetupConstants.LB_PRIMARY_URL];
            submit[SetupConstants.LB_SESSION_HA_SFO] = data[SetupConstants.LB_SESSION_HA_SFO];
        }


        setInstalling(true);
        const setupURL = "./initialSetup";
        const response = await postData(setupURL, data);
        const result = await response.json()
        setInstalling(false)
        if (!result.error) {
            setInstallComplete(true);
        } else {
            setInstallErrorMessage(result.error);
        }
    }

    const backToWizard = () => {
        setInstalling(false);
        setInstallComplete(false);
        setInstallErrorMessage("");
    }

    return (
        <>
            <FormProvider {...methods}>
                <Container>
                    <Card>
                        <CardContent>
                            <Grid container>
                                <Grid size={{ md: 2 }}>
                                    <CustomSettingStepper activeStep={step}></CustomSettingStepper>
                                    <Button
                                        variant="outlined"
                                        color="primary"
                                        onClick={() => navigate("/")}>
                                        {t("button.reset")}
                                    </Button>
                                </Grid>
                                <Grid size={{ md: 10 }}>
                                    {React.createElement(forms[step], {
                                        setStep: setStep
                                    })}
                                    <CardActions sx={{ justifyContent: step === 6 ? "space-between" : "start" }}>
                                        {step > 0 &&
                                            <Button
                                                variant="outlined"
                                                color="primary"
                                                onClick={decrementStep}>
                                                {t("button.previous")}</Button>}
                                        {step !== 6 &&
                                            <Button
                                                id="nextTabButton"
                                                variant="contained"
                                                color="primary"
                                                onClick={methods.handleSubmit(incrementStep)}>
                                                {t("button.next")}</Button>}
                                        {step === 6 &&
                                            <Button
                                                id="writeConfigButton"
                                                variant="contained"
                                                color="primary"
                                                onClick={methods.handleSubmit(submitData)}>
                                                {t("button.create")}</Button>
                                        }
                                    </CardActions>
                                </Grid>
                            </Grid>
                        </CardContent>
                    </Card>
                </Container>
            </FormProvider>
            <InstallDialog
                isInstalling={installing}
                isInstalled={installComplete}
                errorMessage={installErrorMessage}
                onClickBack={backToWizard}
                iframeSrc="../setup/setSetupProgress" />
        </>
    );

};

export default CustomSetting;
