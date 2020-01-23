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
 * Copyright 2020 Open Source Solution Technology Corporation
 */

package jp.co.osstech.openam.shared.cookie;

/**
 * Enumeration that defines the Cookie SameSite attribute.
 */
public enum SameSite {
    STRICT("Strict"),
    LAX("Lax"),
    NONE("None");
    
    private final String attrValue;
    
    /**
     * Constructor.
     * 
     * @param attrValue The attribute value.
     */
    private SameSite(String attrValue) {
        this.attrValue = attrValue;
    }

    /**
     * Get the attribute value.
     * 
     * @return The attribute value.
     */
    public String getValue() {
        return attrValue;
    }

    /**
     * Get SameSite object whose attribute value matches.
     * 
     * @param attrValue The attribute value.
     * @return SameSite object.
     */
    public static SameSite get(String attrValue) {
        for (SameSite samesite : values()) {
            if (samesite.getValue().equalsIgnoreCase(attrValue)) {
                return samesite;
            }
        }
        return null;
    }
}
