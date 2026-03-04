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
package jp.co.osstech.openam.upgrade.helpers;

import java.util.HashSet;
import java.util.Set;

import org.forgerock.openam.upgrade.UpgradeException;

import com.sun.identity.sm.AbstractUpgradeHelper;
import com.sun.identity.sm.AttributeSchemaImpl;

/**
 * This upgrade helper is used to handle Rest Security schema.
 */
public class RestSecurityUpgradeHelper extends AbstractUpgradeHelper {

    private static final String SELF_WRITEABLE_ATTRIBUTES = "selfWriteUserAttributes";

    @Override
    public AttributeSchemaImpl addNewAttribute(Set<AttributeSchemaImpl> existingAttrs, AttributeSchemaImpl newAttr)
            throws UpgradeException {
        if (SELF_WRITEABLE_ATTRIBUTES.equals(newAttr.getName())) {
            updateDefaultValues(newAttr, new HashSet<String>());
        }
        return super.addNewAttribute(existingAttrs, newAttr);
    }

    @Override
    public AttributeSchemaImpl upgradeAttribute(AttributeSchemaImpl oldAttr, AttributeSchemaImpl newAttr)
            throws UpgradeException {
        return newAttr;
    }
}
