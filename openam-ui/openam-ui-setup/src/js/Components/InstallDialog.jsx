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

import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, DialogContentText } from "@mui/material"
import { useTranslation } from "react-i18next"

export const InstallDialog = ({ iframeSrc, isInstalling, isInstalled, errorMessage, onClickBack }) => {
    const { t } = useTranslation();

    return (
        <>
            <Dialog id="inProgress" maxWidth="md" open={isInstalling || isInstalled}>
                <DialogTitle>
                    {t("installing")}
                </DialogTitle>
                <DialogContent>
                    <iframe
                        title="some"
                        src={iframeSrc}
                        scrolling="no"
                        frameborder={0}
                        height={250}
                        width={600}></iframe>
                </DialogContent>
            </Dialog>
            <Dialog id="installComplete" open={isInstalled && !errorMessage}>
                <Box sx={{ m: 1, border: "1px solid #999999" }}>
                    <DialogContent>
                        <DialogContentText variant="h6" color="secondary">
                            {t("configComplete")}
                        </DialogContentText>
                    </DialogContent>
                    <DialogActions>
                        <Button
                            color="primary"
                            onClick={() => window.location.href = "../"}
                            id="gotoLogin"
                        >{t("gotoLogin")}</Button>
                    </DialogActions>
                </Box>
            </Dialog>
            <Dialog id="installError" open={errorMessage}>
                <DialogContent>
                    {errorMessage}
                </DialogContent>
                <DialogActions>
                    <Button
                        variant="outlined"
                        color="primary"
                        onClick={onClickBack}
                    >{t("returnConfig")}</Button>
                </DialogActions>
            </Dialog>
        </>
    )
}
