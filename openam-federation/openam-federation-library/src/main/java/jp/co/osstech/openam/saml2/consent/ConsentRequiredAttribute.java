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
package jp.co.osstech.openam.saml2.consent;

import java.util.Collections;
import java.util.List;

/**
 * The class <code>ConsentRequiredAttribute</code> holds attribute name, display
 * name to be shown in consent page and attribute value of a consent required
 * attribute.
 */
public class ConsentRequiredAttribute {

    private String attributeName;
    private String displayName;
    private List<String> attributeValue;

    ConsentRequiredAttribute(String attributeName, String displayName, List<String> attributeValue) {
        this.attributeName = attributeName;
        this.displayName = displayName;
        this.attributeValue = Collections.unmodifiableList(attributeValue);
    }

    public String attributeName() {
        return attributeName;
    }

    public String displayName() {
        return displayName;
    }

    public List<String> attributeValue() {
        return Collections.unmodifiableList(attributeValue);
    }
}
