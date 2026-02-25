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

import { Step, StepLabel, Stepper } from "@mui/material"
import { useTranslation } from "react-i18next"

export const CustomSettingStepper = ({ activeStep }) => {
    const { t } = useTranslation();
    const steps = [t("sideBar.step1"), t("sideBar.step2"), t("sideBar.step3"), t("sideBar.step4"), t("sideBar.step5"), t("sideBar.step6"), t("sideBar.step7")];

    return (
        <>
            <Stepper activeStep={activeStep} orientation="vertical">
                {steps.map(title =>
                    <Step key={title}>
                        <StepLabel>{title}</StepLabel>
                    </Step>
                )}
            </Stepper>
        </>
    )
}
