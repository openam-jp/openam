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
import { Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel } from '@mui/material';
import { useTranslation } from 'react-i18next';

const LicenseDialog = ({ open, onAgree, onCancel }) => {

    const [license, setLicence] = useState(null);
    const [agree, setAgree] = useState(false);

    const { t } = useTranslation();

    useEffect(() => {
        const getLicense = async () => {
            const targetURL = "../legal-notices/license.txt";
            const response = await fetch(targetURL);
            const text = await response.text();
            setLicence(text.replace(/\r?\n/g, '<br>'));
        }
        getLicense();
    }, []);

    const toggleAgree = (event) => {
        setAgree(event.target.checked);
    }

    return (
        <>
            <Dialog id="wizard_c" open={open} maxWidth="md">
                <DialogTitle>
                    License
                </DialogTitle>
                <DialogContent sx={{ height: 400 }}>
                    <p dangerouslySetInnerHTML={{ __html: license }}></p>
                    <FormControlLabel
                        label="I accept the license agreement"
                        control={<Checkbox
                            id="wizard-accept-check"
                            color="primary"
                            checked={agree}
                            onChange={toggleAgree} />}
                        labelPlacement="start"
                        sx={{
                            backgroundColor: 'action.selected',
                            padding: 1.25
                        }}
                    />
                </DialogContent>
                <DialogActions>
                    <Button
                        id="wizard-accept-license-button"
                        variant="contained"
                        color="primary"
                        disabled={!agree}
                        onClick={onAgree}>Continue</Button>
                    <Button
                        variant="outlined"
                        color="primary"
                        onClick={onCancel}>{t("button.cancel")}</Button>
                </DialogActions>
            </Dialog>
        </>
    )
};

export default LicenseDialog;
