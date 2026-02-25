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

import { Button, Card, CardContent, CardMedia, Container, Grid, Box } from '@mui/material';
import React, { useEffect } from 'react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import LicenseDialog from '../Components/LicenseDialog';
import { useTranslation } from "react-i18next"

export const Install = () => {
    const navigate = useNavigate();
    const [dialogOpen, setDialogOpen] = useState(false);
    const [destination, setDestination] = useState();
    const [showPage, setShowPage] = useState(false)
    const { t } = useTranslation();

    const onClickDefault = () => {
        setDestination("/default");
        setDialogOpen(true);
    }
    const onClickCustom = () => {
        setDestination("/custom");
        setDialogOpen(true);
    }

    useEffect(() => {
        const checkUpgrade = async () => {
            const endpoint = "../upgrade/checkUpgrade";
            const response = await fetch(endpoint);
            const data = await response.json();
            if (data.needUpgrade === "true") {
                navigate("/upgrade");
            } else {
                setShowPage(true);
            }
        }
        checkUpgrade()
    }, [navigate]);

    return (
        <>
            {showPage &&
                <Container>
                    <Card>
                        <CardMedia
                            image="./images/login-logo.png"
                            sx={{
                                paddingTop: 16,
                                backgroundSize: "210px 104px"
                            }}></CardMedia>
                        <CardContent>
                            <Grid container spacing={3}>
                                <Grid size={12}>
                                    <h1>{t("configuration.options.title")}</h1>
                                </Grid>
                                <Grid size={12}>
                                    <Box
                                        component="h3"
                                        sx={{
                                            backgroundColor: 'primary.main',
                                            color: "white",
                                            padding: 0.625,
                                            paddingLeft: 2.5,
                                            margin: 0
                                        }}>{t("configuration.options.subtitle")}</Box>
                                </Grid>
                                <Grid size={6}>
                                    <h3>{t("configuration.options.default.label")}</h3>
                                    <p>{t("configuration.options.default.description")}</p>
                                    <Button id="DemoConfiguration" color="primary" onClick={onClickDefault}>{t("configuration.options.default.link")}</Button>
                                </Grid>
                                <Grid size={6}>
                                    <h3>{t("configuration.options.custom.label")}</h3>
                                    <p>{t("configuration.options.custom.description")}</p>
                                    <Button id="CreateNewConf" color="primary" onClick={onClickCustom}>{t("configuration.options.custom.link")}</Button>
                                </Grid>
                            </Grid>
                        </CardContent>
                    </Card>
                    <LicenseDialog
                        open={dialogOpen}
                        onAgree={() => navigate(destination)}
                        onCancel={() => setDialogOpen(false)}
                    ></LicenseDialog>
                </Container>
            }
        </>
    );

};
