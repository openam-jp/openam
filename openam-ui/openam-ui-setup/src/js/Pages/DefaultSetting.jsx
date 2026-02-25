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

import { useNavigate } from 'react-router-dom';
import { FormProvider, useForm } from 'react-hook-form';
import { useEffect, useState } from 'react';
import { SetupConstants } from '../SetupConstants';
import { Button, Card, CardActions, CardContent, Container, Grid, Step, StepLabel, Stepper } from '@mui/material';
import { PasswordInput } from '../Components/PasswordInput';
import { InstallDialog } from '../Components/InstallDialog';
import { useTranslation } from 'react-i18next';
import { postData } from '../utils/postData';

const DefaultSetting = () => {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const [installing, setInstalling] = useState(false);
    const [installComplete, setInstallComplete] = useState(false);
    const [installErrorMessage, setInstallErrorMessage] = useState("");
    const methods = useForm({ mode: "onChange" });

    const onSubmit = async (data) => {
        setInstalling(true);
        const setupURL = "./initialSetup";
        const response = await postData(setupURL, data)
        const result = await response.json()
        setInstalling(false)
        if (!result.error) {
            setInstallComplete(true);
        } else {
            setInstallErrorMessage(result.error);
        }
    };

    const backToWizard = () => {
        setInstalling(false);
        setInstallComplete(false);
        setInstallErrorMessage("");
    }

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
        }
        getDefaultValues();
    }, []);

    return (
        <>
            <FormProvider {...methods}>
                <Container>
                    <Card>
                        <CardContent>
                            <Grid container>
                                <Grid size={{ md: 2 }}>
                                    <Stepper activeStep={0} orientation="vertical">
                                        <Step key="Credentials">
                                            <StepLabel>{t("sideBar.default")}</StepLabel>
                                        </Step>
                                    </Stepper>
                                    <Button
                                        variant="outlined"
                                        color="primary"
                                        onClick={() => navigate("/")}>{t("button.reset")}</Button>
                                </Grid>
                                <Grid size={{ md: 10 }}>
                                    <h1>{t("default.title")}</h1>
                                    <p>{t("default.description")}</p>

                                    <Card variant="outlined">
                                        <CardContent>
                                            <h3>{t("step1.subtitle")}</h3>
                                            <Grid container spacing={2}>
                                                <Grid size={12}>
                                                    <PasswordInput
                                                        name={SetupConstants.CONFIG_VAR_ADMIN_PWD}
                                                        label={t("label.password")}
                                                        rules={{
                                                            required: t("error.missingRequiredField"),
                                                            minLength: {
                                                                value: 8,
                                                                message: t("error.passwordSizeInvalid")
                                                            },
                                                            validate: () => { methods.trigger(SetupConstants.CONFIG_VAR_CONFIRM_ADMIN_PWD); return true }
                                                        }}
                                                    ></PasswordInput>
                                                </Grid>
                                                <Grid size={12}>
                                                    <PasswordInput
                                                        name={SetupConstants.CONFIG_VAR_CONFIRM_ADMIN_PWD}
                                                        label={t("label.passwordConfirm")}
                                                        rules={{
                                                            required: t("error.missingRequiredField"),
                                                            validate: (value) => value === methods.watch(SetupConstants.CONFIG_VAR_ADMIN_PWD) || t("error.passwordDontMatch")
                                                        }}
                                                    ></PasswordInput>
                                                </Grid>
                                            </Grid>
                                        </CardContent>
                                    </Card>
                                    <Card variant="outlined">
                                        <CardContent>
                                            <h3>{t("step6.subtitle")}</h3>
                                            <Grid container spacing={1}>
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
                                                                triggerValidation: () => { methods.trigger(SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD_CONFIRM); return true },
                                                                differentFromAdmin: (value) => value !== methods.watch(SetupConstants.CONFIG_VAR_ADMIN_PWD) || t("error.agentAdminPasswordSame")
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
                                                            validate: (value) => value === methods.watch(SetupConstants.CONFIG_VAR_AMLDAPUSERPASSWD) || t("error.passwordDontMatch")
                                                        }}
                                                    ></PasswordInput>
                                                </Grid>
                                            </Grid>
                                        </CardContent>
                                    </Card>
                                    <CardActions sx={{ justifyContent: "end" }}>
                                        <Button
                                            variant="contained"
                                            color="primary"
                                            onClick={methods.handleSubmit(onSubmit)}>{t("button.create")}</Button>
                                    </CardActions>
                                </Grid>
                            </Grid>
                        </CardContent>
                    </Card>
                </Container>
                <InstallDialog
                    isInstalling={installing}
                    isInstalled={installComplete}
                    errorMessage={installErrorMessage}
                    onClickBack={backToWizard}
                    iframeSrc="../setup/setSetupProgress"
                ></InstallDialog>
            </FormProvider>
        </>
    );
};

export default DefaultSetting;
