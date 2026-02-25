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

import { TextField } from "@mui/material";
import { Controller, useFormContext } from "react-hook-form";

export const TextInput = ({ name, label, rules, readOnly, ...rest }) => {
    const { control, formState: { errors } } = useFormContext();
    return (
        <>
            <Controller
                name={name}
                control={control}
                rules={rules}
                render={({ field }) => (
                    <TextField
                        variant="standard"
                        id={name}
                        label={label}
                        error={!!errors[name]}
                        helperText={errors[name]?.message}
                        required={!!rules?.required}
                        inputProps={{
                            readOnly: readOnly,
                        }}
                        sx={{
                            width: 350,
                            backgroundColor: readOnly ? 'action.disabledBackground' : 'white'
                        }}
                        onChange={field.onChange}
                        onBlur={field.onBlur}
                        inputRef={field.ref}
                        value={field.value}
                        {...rest}
                    ></TextField>
                )}
            ></Controller>
        </>
    )
}
