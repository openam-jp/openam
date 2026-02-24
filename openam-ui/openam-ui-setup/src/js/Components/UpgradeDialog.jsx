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

export const UpgradeDialog = ({ iframeSrc, isUpgrading, isUpgraded, errorMessage, onClickBack }) => {
    const { t } = useTranslation();

    return (
        <>
            <Dialog maxWidth="md" open={isUpgrading || isUpgraded}>
                <DialogTitle>
                    {t("upgrade.progress")}
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
            <Dialog open={isUpgraded}>
                <Box sx={{ m: 1, border: "1px solid #999999" }}>
                    <DialogContent>
                        <DialogContentText align="center" variant="h6" color="secondary">
                            {t("upgrade.complete")}
                        </DialogContentText>
                        <DialogContentText variant="overline">
                            <p>{t("upgrade.restartContainer")}</p>
                        </DialogContentText>
                    </DialogContent>
                </Box>
            </Dialog>
            <Dialog open={errorMessage}>
                <DialogContent>
                    {errorMessage}
                </DialogContent>
                <DialogActions>
                    <Button
                        variant="outlined"
                        color="primary"
                        onClick={onClickBack}>
                        {t("returnConfig")}
                    </Button>
                </DialogActions>
            </Dialog>
        </>
    )
}
