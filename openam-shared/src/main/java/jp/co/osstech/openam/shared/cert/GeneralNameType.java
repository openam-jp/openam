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

package jp.co.osstech.openam.shared.cert;

/**
 * Represents each type of GeneralName as defined in the X.509 standard.
 * Each enum constant corresponds to a specific type of GeneralName, with an associated integer value.
 * <p>
 * The ASN.1 definition of the GeneralName is:
 * <pre>
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER }
 * </pre>
 */
public enum GeneralNameType {
    /**
     * Represents an otherName (value: 0).
     */
    OTHER_NAME(0),

    /**
     * Represents an rfc822Name (value: 1).
     */
    RFC822_NAME(1),

    /**
     * Represents a dNSName (value: 2).
     */
    DNS_NAME(2),

    /**
     * Represents an x400Address (value: 3).
     */
    X400_ADDRESS(3),

    /**
     * Represents a directoryName (value: 4).
     */
    DIRECTORY_NAME(4),

    /**
     * Represents an ediPartyName (value: 5).
     */
    EDI_PARTY_NAME(5),

    /**
     * Represents a uniformResourceIdentifier (value: 6).
     */
    UNIFORM_RESOURCE_IDENTIFIER(6),

    /**
     * Represents an iPAddress (value: 7).
     */
    IP_ADDRESS(7),

    /**
     * Represents a registeredID (value: 8).
     */
    REGISTERED_ID(8);

    private final int value;

    /**
     * Constructs a {@code GeneralNameType} with the specified integer value.
     *
     * @param value the integer value associated with the {@code GeneralNameType}.
     */
    private GeneralNameType(int value) {
        this.value = value;
    }

    /**
     * Gets the integer value associated with this {@code GeneralNameType}.
     *
     * @return the integer value of the {@code GeneralNameType}.
     */
    public int getIntValue() {
        return value;
    }

    /**
     * Gets the {@code GeneralNameType} corresponding to the specified integer value.
     *
     * @param value the integer value to convert to a {@code GeneralNameType}.
     * @return the {@code GeneralNameType} corresponding to the given value.
     * @throws IllegalArgumentException if the {@code value} is less than 0 or greater than 8.
     */
    public static GeneralNameType fromIntValue(int value) {
        switch (value) {
        case 0:
            return OTHER_NAME;
        case 1:
            return RFC822_NAME;
        case 2:
            return DNS_NAME;
        case 3:
            return X400_ADDRESS;
        case 4:
            return DIRECTORY_NAME;
        case 5:
            return EDI_PARTY_NAME;
        case 6:
            return UNIFORM_RESOURCE_IDENTIFIER;
        case 7:
            return IP_ADDRESS;
        case 8:
            return REGISTERED_ID;
        default:
            throw new IllegalArgumentException("Invalid value: " + value);
        }
    }
}
