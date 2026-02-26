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

import java.util.Set;

import org.forgerock.openam.utils.CollectionUtils;

import com.sun.identity.common.configuration.AgentConfiguration;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * AttributeSchemaFilter implementation for agents.
 */
public class AgentAttributeSchemaFilter implements AttributeSchemaFilter {

    Set<String> REQUIRED_ATTRIBUTES_TO_EXCLUDE =
            CollectionUtils.asSet("sunIdentityServerDeviceStatus",
                    "com.forgerock.openam.oauth2provider.clientType",
                    "publish-service-poll-interval");

    @Override
    public boolean isTarget(AttributeSchema schema) {
        if (schema.getName().equals(AgentConfiguration.ATTR_NAME_GROUP)) {
            return true;
        }

        String i18NKey = schema.getI18NKey();
        return i18NKey != null && i18NKey.length() > 0;
    }

    @Override
    public boolean isRequired(AttributeSchema schema) {
        String validator = schema.getValidator();
        if (validator != null
                && RequiredValueValidator.class.getSimpleName().equals(validator)
                && !REQUIRED_ATTRIBUTES_TO_EXCLUDE.contains(schema.getName())) {
            return true;
        }
        return false;
    }
}
