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

import { Checkbox, FormControlLabel } from "@mui/material"
import { Controller, useFormContext } from "react-hook-form"

export const CheckboxInput = ({ name, label, disabled }) => {
    const { control } = useFormContext()
    return (
        <>
            <Controller
                name={name}
                control={control}
                render={({ field }) => (
                    <FormControlLabel
                        label={label}
                        control={
                            <Checkbox
                                id={name}
                                onBlur={field.onBlur}
                                onChange={(e) => field.onChange(e.target.checked)}
                                color="primary"
                                checked={field.value}
                                inputRef={field.ref}
                                disabled={disabled} />
                        }></FormControlLabel>
                )}></Controller>
        </>
    )
}
