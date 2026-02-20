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

package jp.co.osstech.openam.core.rest.sms;

import com.sun.identity.sm.AttributeSchema;

/**
 * Default AttributeSchemaFilter implementation.
 */
public class DefaultAttributeSchemaFilter implements AttributeSchemaFilter {

    @Override
    public boolean isTarget(AttributeSchema schema) {
        String i18NKey = schema.getI18NKey();
        return i18NKey != null && i18NKey.length() > 0;
    }

    @Override
    public boolean isRequired(AttributeSchema schema) {
        return !schema.isOptional();
    }
}
