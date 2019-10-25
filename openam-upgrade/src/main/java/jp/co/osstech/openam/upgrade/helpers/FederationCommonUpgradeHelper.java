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
 * Copyright 2019 Open Source Solution Technology Corporation
 */
package jp.co.osstech.openam.upgrade.helpers;

import static org.forgerock.openam.utils.CollectionUtils.*;

import java.util.Set;

import com.sun.identity.sm.AbstractUpgradeHelper;
import com.sun.identity.sm.AttributeSchemaImpl;
import com.sun.identity.xmlenc.EncryptionConstants;
import org.forgerock.openam.upgrade.UpgradeException;

/**
 * This upgrade helper is used to add new default values to 
 * the Common Federation Configuration schema.
 */
public class FederationCommonUpgradeHelper extends AbstractUpgradeHelper {
    
    private static final String XMLENC_KEY_TRANSPORT_ALGORITHM = "EncryptionKeyTransportAlgorithm";

    public FederationCommonUpgradeHelper() {
    }

    @Override
    public AttributeSchemaImpl addNewAttribute(Set<AttributeSchemaImpl> existingAttrs, AttributeSchemaImpl newAttr)
            throws UpgradeException {
        // Keep RSA-v1.5 if upgrading from older versions
        if (XMLENC_KEY_TRANSPORT_ALGORITHM.equals(newAttr.getName())) {
            updateDefaultValues(newAttr, asSet(EncryptionConstants.ENC_KEY_ENC_METHOD_RSA_1_5));
        }
        return newAttr;
    }

    @Override
    public AttributeSchemaImpl upgradeAttribute(AttributeSchemaImpl oldAttr, AttributeSchemaImpl newAttr)
            throws UpgradeException {
        return newAttr;
    }
    
}
