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

import { Button, Card, CardActions, CardContent, Container, Box } from "@mui/material";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import LicenseDialog from "../Components/LicenseDialog";
import { UpgradeDialog } from "../Components/UpgradeDialog"

const Upgrade = () => {
    const [upgradeInfo, setUpgradeInfo] = useState();
    const [licenseDialogOpen, setLicenseDialogOpen] = useState(false);
    const [isUpgrading, setIsUpgrading] = useState(false);
    const [isUpgraded, setIsUpgraded] = useState(false);
    const [licenseAgree, setLicenseAgree] = useState(false);
    const [upgradeErrorMessage, setUpgradeErrorMessage] = useState("");
    const { t } = useTranslation();
    const navigate = useNavigate();

    useEffect(() => {
        const getUpgradeInfo = async () => {
            const responce = await fetch("../upgrade/checkUpgrade");
            const data = await responce.json();
            if (data.needUpgrade === "false") {
                navigate("/");
            }
            if (data.upgradeCompleted === "true") {
                setIsUpgraded(true);
            }
            setUpgradeInfo(data);
        };
        getUpgradeInfo();
    }, []);

    const agreeLicense = () => {
        setLicenseAgree(true);
        setLicenseDialogOpen(false);
    }

    const doUpgrade = async () => {
        setLicenseDialogOpen(false);
        setIsUpgrading(true);
        const response = await fetch("../upgrade/doUpgrade");
        const result = await response.json();
        if (!result.error) {
            setIsUpgraded(true);
        } else {
            setUpgradeErrorMessage(result.error);
        }
    }

    const backToWizard = () => {
        setIsUpgrading(false);
        setIsUpgraded(false);
        setUpgradeErrorMessage("");
    }

    const saveReport = () => {
        window.open("../upgrade/checkUpgrade?saveReport=true", "Download");
    }

    const version = import.meta.env.VITE_VERSION;
    const upgradeTilte = t("upgrade.subtitle").replace("${project.version}", version);
    const upgradeLink = t("upgrade.link").replace("${project.version}", version);

    return (
        <>
            <Container>
                <Card>
                    <CardContent>
                        {licenseAgree ?
                            <h1>{upgradeTilte}</h1> :
                            <h1>{t("upgrade.available")}</h1>
                        }
                        {!upgradeInfo && <h4>Loading...</h4>}
                        {upgradeInfo && !licenseAgree &&
                            <>
                                <h3>{t("upgrade.newVersionFound")}</h3>
                                <p>{upgradeInfo.currentVersion}</p>
                                <h3>{upgradeTilte}</h3>
                                <p dangerouslySetInnerHTML={{ __html: t("upgrade.description") }}></p>
                                <Button
                                    variant="outlined"
                                    color="primary"
                                    onClick={() => setLicenseDialogOpen(true)}>{upgradeLink}</Button>
                            </>}
                        {upgradeInfo && licenseAgree &&
                            <>
                                <p>{t("upgrade.currentVersion")} <span>{upgradeInfo.currentVersion}</span></p>
                                <p>{t("upgrade.newVersion")} <span>{upgradeInfo.newVersion}</span></p>
                                <Box
                                    component="div"
                                    dangerouslySetInnerHTML={{ __html: upgradeInfo.changelist }}
                                    sx={{
                                        borderStyle: "solid",
                                        borderWidth: 1,
                                        padding: 1.25
                                    }}></Box>
                            </>
                        }
                    </CardContent>
                    {upgradeInfo && licenseAgree &&
                        <CardActions>
                            <Button
                                variant="contained"
                                color="primary"
                                onClick={doUpgrade}>
                                {t("button.upgrade")}
                            </Button>
                            <Button
                                variant="outlined"
                                color="primary"
                                onClick={saveReport}>
                                {t("button.saveReport")}
                            </Button>
                        </CardActions>
                    }
                </Card>
            </Container>
            <LicenseDialog
                open={licenseDialogOpen}
                onAgree={agreeLicense}
                onCancel={() => setLicenseDialogOpen(false)}></LicenseDialog>
            <UpgradeDialog
                iframeSrc="../upgrade/setUpgradeProgress"
                isUpgrading={isUpgrading}
                isUpgraded={isUpgraded}
                errorMessage={upgradeErrorMessage}
                onClickBack={backToWizard}
            ></UpgradeDialog>
        </>
    )
}

export default Upgrade;
