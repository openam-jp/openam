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

package jp.co.osstech.openam.core.rest.identities;

import java.util.HashSet;
import java.util.Set;

import com.sun.identity.sm.AttributeSchema;
import jp.co.osstech.openam.core.rest.sms.AttributeSchemaFilter;
import org.forgerock.openam.utils.CollectionUtils;

/**
 * AttributeSchemaFilter implementation for entities.
 */
public class EntitiesAttributeSchemaFilter implements AttributeSchemaFilter {

    @Override
    public boolean isTarget(AttributeSchema schema) {
        String i18NKey = schema.getI18NKey();
        if (i18NKey == null || i18NKey.isEmpty()) {
            return false;
        }

        if (schema.getUIType() == AttributeSchema.UIType.LINK) {
            // Exclude items where uitype is "link".
            // ChangePassword, iplanet-am-user-auth-config, etc.
            return false;
        }

        if (schema.getName().equalsIgnoreCase("userpassword")) {
            return true;
        }

        Set<String> any = getDelimitedValues(schema.getAny());
        if (any.contains("display") || any.contains("adminDisplay")) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isRequired(AttributeSchema schema) {
        Set<String> any = getDelimitedValues(schema.getAny());
        if (any.contains("required")) {
            return true;
        }
        return false;
    }

    private Set<String> getDelimitedValues(String any) {
        Set<String> values = new HashSet<String>();
        if ((any != null) && (any.trim().length() > 0)) {
            values = CollectionUtils.asSet(any.split("\\|"));
        }
        return values;
    }
}
