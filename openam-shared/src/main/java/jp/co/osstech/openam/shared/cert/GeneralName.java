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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Represents a GeneralName as defined in the X.509 standard.
 * This class encapsulates the name type and value, and provides methods to extract and convert
 * these values into various formats.
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
public final class GeneralName {

    private final GeneralNameType nameType;
    private final ASN1Encodable nameValue;
    private final OtherName otherName;

    /**
     * Constructs a {@code GeneralName} instance from a Bouncy Castle {@code GeneralName} object.
     *
     * @param generalName the Bouncy Castle {@code GeneralName} object to extract name type and value.
     *         Must not be {@code null}.
     * @throws IllegalArgumentException if the {@code generalName} argument is {@code null}.
     */
    GeneralName(org.bouncycastle.asn1.x509.GeneralName generalName) throws IllegalArgumentException {
        if (generalName == null) {
            throw new IllegalArgumentException("generalName must not be null");
        }
        nameType = GeneralNameType.fromIntValue(generalName.getTagNo());
        nameValue = generalName.getName();
        if (nameType == GeneralNameType.OTHER_NAME) {
            otherName = OtherName.getInstance(nameValue);
        } else {
            otherName = null;
        }
    }

    /**
     * Gets the name type.
     *
     * @return the {@code GeneralNameType} representing the name type.
     */
    public GeneralNameType getNameType() {
        return nameType;
    }

    /**
     * Gets the name value as a {@code byte[]} in ASN.1 DER encoded format.
     *
     * @return the ASN.1 DER encoded {@code byte[]} representing the name value.
     * @throws IOException if an error occurs during the encoding process.
     */
    public byte[] getNameValueAsBytes() throws IOException {
        return nameValue.toASN1Primitive().getEncoded("DER");
    }

    /**
     * Attempts to get the name value as a {@code String}.
     * <p>
     * The ASN.1 definition of GeneralName is:
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
     * If the name type is in the following list, this method returns a {@code String} representing
     * the name value:
     * <ul>
     *   <li>rfc822Name: Email addresses, e.g., returns {@code "user@example.com"}</li>
     *   <li>dNSName: Domain names, e.g., returns {@code "example.com"}</li>
     *   <li>directoryName: Distinguished names, e.g., returns {@code "CN=Example,O=Company,C=JP"}</li>
     *   <li>uniformResourceIdentifier: URIs, e.g., returns {@code "https://example.com"}</li>
     *   <li>registeredID: Object identifiers, e.g., returns {@code "2.5.4.3"}</li>
     *   <li>iPAddress:
     *     <ul>
     *       <li>IPv4 addresses, e.g., returns {@code "192.0.2.1"}, {@code "192.0.2.0/255.255.255.0"}</li>
     *       <li>IPv6 addresses, e.g., returns {@code "2001:db8:0:0:0:0:0:1"}, {@code "2001:db8:0:0:0:0:0:0/32"}</li>
     *     </ul>
     *   </li>
     * </ul>
     * If the name type is otherName, x400Address or ediPartyName, this method returns {@code null}.
     *
     * @return a {@code String} representing the name value if the name value can be represented as a
     *         {@code String}, {@code null} otherwise.
     * @throws IOException if an error occurs during the encoding process.
     */
    public String getNameValueAsString() throws IOException {
        switch (nameType) {
        case RFC822_NAME:
        case DNS_NAME:
        case UNIFORM_RESOURCE_IDENTIFIER:
            return ((ASN1String) nameValue).getString();
        case DIRECTORY_NAME:
            X500Principal principal = new X500Principal(nameValue.toASN1Primitive().getEncoded("DER"));
            return principal.getName(X500Principal.RFC2253);
        case IP_ADDRESS:
            byte[] addressBytes = ((ASN1OctetString) nameValue).getOctets();
            return convertOctetsToIPAddressString(addressBytes);
        case REGISTERED_ID:
            return ((ASN1ObjectIdentifier) nameValue).getId();
        default:
            return null;
        }
    }

    /**
     * Attempts to get the type-id of the OtherName.
     * <p>
     * The ASN.1 definition of OtherName is:
     * <pre>
     * OtherName ::= SEQUENCE {
     *      type-id    OBJECT IDENTIFIER,
     *      value      [0] EXPLICIT ANY DEFINED BY type-id }
     * </pre>
     * If the name type is otherName, this method returns a {@code String} representing the type-id.
     * Otherwise, this method returns {@code null}.
     *
     * @return a {@code String} representing the type-id if the name type is otherName, {@code null} otherwise.
     */
    public String getOtherNameTypeId() {
        if (nameType != GeneralNameType.OTHER_NAME) {
            return null;
        }
        return otherName.getTypeID().getId();
    }

    /**
     * Attempts to get the value of the OtherName as a {@code byte[]} in ASN.1 DER
     * encoded format (excluding the context-specific constructed tag [0]).
     * <p>
     * The ASN.1 definition of OtherName is:
     * <pre>
     * OtherName ::= SEQUENCE {
     *      type-id    OBJECT IDENTIFIER,
     *      value      [0] EXPLICIT ANY DEFINED BY type-id }
     * </pre>
     * If the name type is otherName, this method returns an ASN.1 DER encoded {@code byte[]}
     * representing the value.
     * Otherwise, this method returns {@code null}.
     *
     * @return an ASN.1 DER encoded {@code byte[]} (excluding the context-specific constructed tag [0])
     *         representing the value if the name type is otherName, {@code null} otherwise.
     * @throws IOException if an error occurs during the encoding process.
     */
    public byte[] getOtherNameValueAsBytes() throws IOException {
        if (nameType != GeneralNameType.OTHER_NAME) {
            return null;
        }
        return otherName.getValue().toASN1Primitive().getEncoded("DER");
    }

    /**
     * Attempts to get the value of the OtherName as a {@code String}.
     * <p>
     * The ASN.1 definition of OtherName is:
     * <pre>
     * OtherName ::= SEQUENCE {
     *      type-id    OBJECT IDENTIFIER,
     *      value      [0] EXPLICIT ANY DEFINED BY type-id }
     * </pre>
     * If the name type is otherName and the value can be represented as a {@code String},
     * this method returns a {@code String}.
     * Otherwise, this method returns {@code null}.
     *
     * @return a {@code String} representing the value if the name type is otherName and the value can
     *         be represented as a {@code String}, {@code null} otherwise.
     */
    public String getOtherNameValueAsString() {
        if (nameType != GeneralNameType.OTHER_NAME) {
            return null;
        }
        ASN1Encodable otherNameValue = otherName.getValue();
        if (otherNameValue instanceof ASN1String) {
            return ((ASN1String) otherNameValue).getString();
        } else {
            return null;
        }
    }

    /**
     * Returns a string representation of this {@code GeneralName}.
     *
     * @return a {@code String} representing this {@code GeneralName}.
     */
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(nameType + ": ");
        if (nameType == GeneralNameType.OTHER_NAME) {
            builder.append("[" + getOtherNameTypeId() + ": ");
            String otherNameValue;
            try {
                String otherNameValueStr = getOtherNameValueAsString();
                if (otherNameValueStr != null) {
                    otherNameValue = otherNameValueStr;
                } else {
                    otherNameValue = "0x" + Hex.toHexString(getOtherNameValueAsBytes());
                }
            } catch (Exception e) {
                otherNameValue = otherName.getValue().toString();
            }
            builder.append(otherNameValue + "]");
        } else {
            String nameValue;
            try {
                String nameValueStr = getNameValueAsString();
                if (nameValueStr != null) {
                    nameValue = nameValueStr;
                } else {
                    nameValue = "0x" + Hex.toHexString(getNameValueAsBytes());
                }
            } catch (Exception e) {
                nameValue = this.nameValue.toString();
            }
            builder.append(nameValue);
        }
        return builder.toString();
    }

    private static String convertOctetsToIPAddressString(byte[] octets) throws UnknownHostException {
        String ipAddress;
        if (octets.length == 4 || octets.length == 8) {
            ipAddress = InetAddress.getByAddress(Arrays.copyOf(octets, 4)).getHostAddress();
            if (octets.length == 8) {
                ipAddress = ipAddress + "/" + InetAddress.getByAddress(Arrays.copyOfRange(octets, 4, 8)).getHostAddress();
            }
            return ipAddress;
        } else {
            ipAddress = InetAddress.getByAddress(Arrays.copyOf(octets, 16)).getHostAddress();
            if (octets.length == 32) {
                ipAddress = ipAddress + "/" + convertMaskToPrefixLength(Arrays.copyOfRange(octets, 16, 32));
            }
        }
        return ipAddress;
    }

    private static int convertMaskToPrefixLength(byte[] mask) {
        int prefixLength = 0;
        boolean foundZero = false;
        for (int i = 0; i < mask.length; i++) {
            byte b = mask[i];
            for (int shiftBits = 7; shiftBits >= 0; shiftBits--) {
                boolean isOne = ((b >> shiftBits) & 1) == 1;
                if (isOne) {
                    if (foundZero) {
                        throw new IllegalArgumentException("non-continuous bits found");
                    }
                    prefixLength++;
                } else {
                    foundZero = true;
                }
            }
        }
        return prefixLength;
    }
}
