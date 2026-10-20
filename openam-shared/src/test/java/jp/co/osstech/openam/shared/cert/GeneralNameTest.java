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

import static org.assertj.core.api.Assertions.*;

import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

// The ASN.1 definition of GeneralName is following:
//
// GeneralName ::= CHOICE {
//      otherName                       [0]     OtherName,
//      rfc822Name                      [1]     IA5String,
//      dNSName                         [2]     IA5String,
//      x400Address                     [3]     ORAddress,
//      directoryName                   [4]     Name,
//      ediPartyName                    [5]     EDIPartyName,
//      uniformResourceIdentifier       [6]     IA5String,
//      iPAddress                       [7]     OCTET STRING,
//      registeredID                    [8]     OBJECT IDENTIFIER }
public class GeneralNameTest {

    @Test
    public void testOtherName() throws Exception {
        // See above for the ASN.1 definition of GeneralName.
        // The ASN.1 definition of otherName is following:
        //
        // OtherName ::= SEQUENCE {
        //      type-id    OBJECT IDENTIFIER,
        //      value      [0] EXPLICIT ANY DEFINED BY type-id }
        //
        // Binary data structure used for testing is following:
        //
        // a0 20                                        -- [CONTEXT-SPECIFIC 0] (otherName)
        //    06 0a 2b060104018237140203                -- OBJECT IDENTIFIER (type-id) 1.3.6.1.4.1.311.20.2.3 (userPrincipalName)
        //    a0 12                                     -- [CONTEXT-SPECIFIC 0] (value)
        //       0c 10 74657374406578616d706c652e636f6d -- UTF8STRING "test@example.com"
        //
        // a0 10                                        -- [CONTEXT-SPECIFIC 0] (otherName)
        //    06 0a 2b060104018237140203                -- OBJECT IDENTIFIER (type-id) 1.3.6.1.4.1.311.20.2.3 (userPrincipalName)
        //    a0 02                                     -- [CONTEXT-SPECIFIC 0] (value)
        //       05 00                                  -- NULL
        GeneralName generalName1 = new GeneralName(org.bouncycastle.asn1.x509.GeneralName.getInstance(
                Hex.decode("a020060a2b060104018237140203a0120c1074657374406578616d706c652e636f6d")));
        assertThat(generalName1.getNameType()).isEqualTo(GeneralNameType.OTHER_NAME);
        // 30 20                                        -- SEQUENCE
        //    06 0a 2b060104018237140203                -- OBJECT IDENTIFIER 1.3.6.1.4.1.311.20.2.3
        //    a0 12                                     -- [CONTEXT-SPECIFIC 0]
        //       0c 10 74657374406578616d706c652e636f6d -- UTF8STRING "test@example.com"
        assertThat(Hex.toHexString(generalName1.getNameValueAsBytes()))
                .isEqualTo("3020060a2b060104018237140203a0120c1074657374406578616d706c652e636f6d");
        assertThat(generalName1.getNameValueAsString()).isNull();
        assertThat(generalName1.toString()).isEqualTo("OTHER_NAME: [1.3.6.1.4.1.311.20.2.3: test@example.com]");

        assertThat(generalName1.getOtherNameTypeId()).isEqualTo("1.3.6.1.4.1.311.20.2.3");
        // 0c 10 74657374406578616d706c652e636f6d -- UTF8STRING "test@example.com"
        assertThat(Hex.toHexString(generalName1.getOtherNameValueAsBytes()))
                .isEqualTo("0c1074657374406578616d706c652e636f6d");
        assertThat(generalName1.getOtherNameValueAsString()).isEqualTo("test@example.com");

        GeneralName generalName2 = new GeneralName(org.bouncycastle.asn1.x509.GeneralName.getInstance(
                Hex.decode("a010060a2b060104018237140203a0020500")));
        assertThat(generalName2.getNameType()).isEqualTo(GeneralNameType.OTHER_NAME);
        // 30 10                         -- SEQUENCE
        //    06 0a 2b060104018237140203 -- OBJECT IDENTIFIER 1.3.6.1.4.1.311.20.2.3
        //    a0 02                      -- [CONTEXT-SPECIFIC 0]
        //       05 00                   -- NULL
        assertThat(Hex.toHexString(generalName2.getNameValueAsBytes()))
                .isEqualTo("3010060a2b060104018237140203a0020500");
        assertThat(generalName2.getNameValueAsString()).isNull();
        assertThat(generalName2.toString()).isEqualTo("OTHER_NAME: [1.3.6.1.4.1.311.20.2.3: 0x0500]");

        assertThat(generalName2.getOtherNameTypeId()).isEqualTo("1.3.6.1.4.1.311.20.2.3");
        // 05 00 -- NULL
        assertThat(Hex.toHexString(generalName2.getOtherNameValueAsBytes())).isEqualTo("0500");
        assertThat(generalName2.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testRFC822Name() throws Exception {
        GeneralName generalName = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
            org.bouncycastle.asn1.x509.GeneralName.rfc822Name, "test@example.com"));
        assertThat(generalName.getNameType()).isEqualTo(GeneralNameType.RFC822_NAME);
        // 16 10 74657374406578616d706c652e636f6d -- IA5STRING "test@example.com"
        assertThat(Hex.toHexString(generalName.getNameValueAsBytes()))
                .isEqualTo("161074657374406578616d706c652e636f6d");
        assertThat(generalName.getNameValueAsString()).isEqualTo("test@example.com");
        assertThat(generalName.toString()).isEqualTo("RFC822_NAME: test@example.com");

        // check if other name related methods return null when the name type is RFC822_NAME
        assertThat(generalName.getOtherNameTypeId()).isNull();
        assertThat(generalName.getOtherNameValueAsBytes()).isNull();
        assertThat(generalName.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testDNSName() throws Exception {
        GeneralName generalName1 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.dNSName, "test.example.com"));
        assertThat(generalName1.getNameType()).isEqualTo(GeneralNameType.DNS_NAME);
        // 16 10 746573742e6578616d706c652e636f6d -- IA5STRING "test.example.com"
        assertThat(Hex.toHexString(generalName1.getNameValueAsBytes()))
                .isEqualTo("1610746573742e6578616d706c652e636f6d");
        assertThat(generalName1.getNameValueAsString()).isEqualTo("test.example.com");
        assertThat(generalName1.toString()).isEqualTo("DNS_NAME: test.example.com");

        GeneralName generalName2 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.dNSName, "*.example.com"));
        assertThat(generalName2.getNameType()).isEqualTo(GeneralNameType.DNS_NAME);
        // 16 0d 2a2e6578616d706c652e636f6d -- IA5STRING "*.example.com"
        assertThat(Hex.toHexString(generalName2.getNameValueAsBytes()))
                .isEqualTo("160d2a2e6578616d706c652e636f6d");
        assertThat(generalName2.getNameValueAsString()).isEqualTo("*.example.com");
        assertThat(generalName2.toString()).isEqualTo("DNS_NAME: *.example.com");

        // check if other name related methods return null when the name type is DNS_NAME
        assertThat(generalName1.getOtherNameTypeId()).isNull();
        assertThat(generalName1.getOtherNameValueAsBytes()).isNull();
        assertThat(generalName1.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testX400Adress() throws Exception {
        // See above for the ASN.1 definition of GeneralName.
        // The ASN.1 definition of ORAddress is following
        // (only sections relevant to this test are listed):
        //
        // ORAddress ::= SEQUENCE {
        //      built-in-standard-attributes BuiltInStandardAttributes,
        //      built-in-domain-defined-attributes
        //                      BuiltInDomainDefinedAttributes OPTIONAL,
        //      -- see also teletex-domain-defined-attributes
        //      extension-attributes ExtensionAttributes OPTIONAL }
        //
        // BuiltInStandardAttributes ::= SEQUENCE {
        //    country-name                  CountryName OPTIONAL,
        //    administration-domain-name    AdministrationDomainName OPTIONAL,
        //    network-address           [0] IMPLICIT NetworkAddress OPTIONAL,
        //      -- see also extended-network-address
        //    terminal-identifier       [1] IMPLICIT TerminalIdentifier OPTIONAL,
        //    private-domain-name       [2] PrivateDomainName OPTIONAL,
        //    organization-name         [3] IMPLICIT OrganizationName OPTIONAL,
        //      -- see also teletex-organization-name
        //    numeric-user-identifier   [4] IMPLICIT NumericUserIdentifier
        //                                  OPTIONAL,
        //    personal-name             [5] IMPLICIT PersonalName OPTIONAL,
        //      -- see also teletex-personal-name
        //    organizational-unit-names [6] IMPLICIT OrganizationalUnitNames
        //                                  OPTIONAL }
        //      -- see also teletex-organizational-unit-names
        //
        // CountryName ::= [APPLICATION 1] CHOICE {
        //    x121-dcc-code         NumericString
        //                            (SIZE (ub-country-name-numeric-length)),
        //    iso-3166-alpha2-code  PrintableString
        //                            (SIZE (ub-country-name-alpha-length)) }
        //
        // Binary data structure used for testing is following:
        //
        // a3 08               -- [CONTEXT-SPECIFIC 3] (x400Address)
        //    30 06            -- SEQUENCE (built-in-standard-attributes)
        //       61 04         -- [APPLICATION 1] (country-name)
        //          13 02 4a50 -- PRINTABLESTRING "JP"
        GeneralName generalName = new GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.getInstance(Hex.decode("a3083006610413024a50")));
        assertThat(generalName.getNameType()).isEqualTo(GeneralNameType.X400_ADDRESS);
        // 30 08               -- SEQUENCE
        //    30 06            -- SEQUENCE
        //       61 04         -- [APPLICATION 1]
        //          13 02 4a50 -- PRINTABLESTRING "JP"
        assertThat(Hex.toHexString(generalName.getNameValueAsBytes())).isEqualTo("30083006610413024a50");
        assertThat(generalName.getNameValueAsString()).isNull();
        assertThat(generalName.toString()).isEqualTo("X400_ADDRESS: 0x30083006610413024a50");

        // check if other name related methods return null when the name type is X400_ADDRESS
        assertThat(generalName.getOtherNameTypeId()).isNull();
        assertThat(generalName.getOtherNameValueAsBytes()).isNull();
        assertThat(generalName.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testDirectoryName() throws Exception {
        GeneralName generalName1 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.directoryName, "C=JP,O=Company,CN=Example"));
        assertThat(generalName1.getNameType()).isEqualTo(GeneralNameType.DIRECTORY_NAME);
        // 30 31                                     -- SEQUENCE
        //    31 0b 3009060355040613024a50           -- C  = "JP"
        //    31 10 300e060355040a0c07436f6d70616e79 -- O  = "Company"
        //    31 10 300e06035504030c074578616d706c65 -- CN = "Example"
        assertThat(Hex.toHexString(generalName1.getNameValueAsBytes()))
                .isEqualTo("3031310b3009060355040613024a503110300e060355040a0c07436f6d70616e793110300e06035504030c0745"
                        + "78616d706c65");
        assertThat(generalName1.getNameValueAsString()).isEqualTo("CN=Example,O=Company,C=JP");
        assertThat(generalName1.toString()).isEqualTo("DIRECTORY_NAME: CN=Example,O=Company,C=JP");

        GeneralName generalName2 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.directoryName,
                "DC=Test-DC,C=Test-C,ST=Test-ST,L=Test-L,"
                        + "STREET=Test-STREET,O=Test-O,OU=Test-OU,CN=Test-CN,UID=Test-UID"));
        assertThat(generalName2.getNameType()).isEqualTo(GeneralNameType.DIRECTORY_NAME);
        // 30 81b2                                                   -- SEQUENCE
        //    31 17 3015060a0992268993f22c6401191607546573742d4443   -- DC     = "Test-DC"
        //    31 0f 300d06035504061306546573742d43                   -- C      = "Test-C"
        //    31 10 300e06035504080c07546573742d5354                 -- ST     = "Test-ST"
        //    31 0f 300d06035504070c06546573742d4c                   -- L      = "Test-L"
        //    31 14 301206035504090c0b546573742d535452454554         -- STREET = "Test-STREET"
        //    31 0f 300d060355040a0c06546573742d4f                   -- O      = "Test-O"
        //    31 10 300e060355040b0c07546573742d4f55                 -- OU     = "Test-OU"
        //    31 10 300e06035504030c07546573742d434e                 -- CN     = "Test-CN"
        //    31 18 3016060a0992268993f22c6401010c08546573742d554944 -- UID    = "Test-UID"
        //
        assertThat(Hex.toHexString(generalName2.getNameValueAsBytes()))
                .isEqualTo("3081b231173015060a0992268993f22c6401191607546573742d4443310f300d06035504061306546573742d43"
                        + "3110300e06035504080c07546573742d5354310f300d06035504070c06546573742d4c3114301206035504090c"
                        + "0b546573742d535452454554310f300d060355040a0c06546573742d4f3110300e060355040b0c07546573742d"
                        + "4f553110300e06035504030c07546573742d434e31183016060a0992268993f22c6401010c08546573742d554944");
        assertThat(generalName2.getNameValueAsString())
                .isEqualTo("UID=Test-UID,CN=Test-CN,OU=Test-OU,O=Test-O,STREET=Test-STREET,"
                        + "L=Test-L,ST=Test-ST,C=Test-C,DC=Test-DC");
        assertThat(generalName2.toString()).isEqualTo("DIRECTORY_NAME: UID=Test-UID,CN=Test-CN,OU=Test-OU,O=Test-O,"
                + "STREET=Test-STREET,L=Test-L,ST=Test-ST,C=Test-C,DC=Test-DC");

        GeneralName generalName3 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.directoryName,
                "C=JP,O=Company,SURNAME=Example,GIVENNAME=Test"));
        assertThat(generalName3.getNameType()).isEqualTo(GeneralNameType.DIRECTORY_NAME);
        // 30 40                                     -- SEQUENCE
        //    31 0b 3009060355040613024a50           -- C         = "JP"
        //    31 10 300e060355040a0c07436f6d70616e79 -- O         = "Company"
        //    31 10 300e06035504040c074578616d706c65 -- SURNAME   = "Example"
        //    31 0d 300b060355042a0c0454657374       -- GIVENNAME = "Test"
        assertThat(Hex.toHexString(generalName3.getNameValueAsBytes()))
                .isEqualTo("3040310b3009060355040613024a503110300e060355040a0c07436f6d70616e793110300e06035504040c0745"
                        + "78616d706c65310d300b060355042a0c0454657374");
        assertThat(generalName3.getNameValueAsString())
                .isEqualTo("2.5.4.42=#0c0454657374,2.5.4.4=#0c074578616d706c65,O=Company,C=JP");
        assertThat(generalName3.toString()).isEqualTo("DIRECTORY_NAME: 2.5.4.42=#0c0454657374,"
                + "2.5.4.4=#0c074578616d706c65,O=Company,C=JP");

        // check if other name related methods return null when the name type is DIRECTORY_NAME
        assertThat(generalName1.getOtherNameTypeId()).isNull();
        assertThat(generalName1.getOtherNameValueAsBytes()).isNull();
        assertThat(generalName1.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testEdiPartyName() throws Exception {
        // See above for the ASN.1 definition of GeneralName.
        // The ASN.1 definition of EDIPartyName is following:
        //
        // EDIPartyName ::= SEQUENCE {
        //      nameAssigner            [0]     DirectoryString OPTIONAL,
        //      partyName               [1]     DirectoryString }
        //
        // DirectoryString ::= CHOICE {
        //      teletexString       TeletexString   (SIZE (1..MAX)),
        //      printableString     PrintableString (SIZE (1..MAX)),
        //      universalString     UniversalString (SIZE (1..MAX)),
        //      utf8String          UTF8String      (SIZE (1..MAX)),
        //      bmpString           BMPString       (SIZE (1..MAX)) }
        //
        // Binary data structure used for testing is following:
        //
        // a5 08                -- [CONTEXT-SPECIFIC 5] (ediPartyName)
        //    a1 06             -- [CONTEXT-SPECIFIC 1] (partyName)
        //       0c 04 54657374 -- UTF8STRING "Test"
        GeneralName generalName = new GeneralName(org.bouncycastle.asn1.x509.GeneralName
                .getInstance(Hex.decode("a508a1060c0454657374")));
        assertThat(generalName.getNameType()).isEqualTo(GeneralNameType.EDI_PARTY_NAME);
        // 30 08                -- SEQUENCE
        //    a1 06             -- [CONTEXT-SPECIFIC 1]
        //       0c 04 54657374 -- UTF8STRING "Test"
        assertThat(Hex.toHexString(generalName.getNameValueAsBytes())).isEqualTo("3008a1060c0454657374");
        assertThat(generalName.getNameValueAsString()).isNull();
        assertThat(generalName.toString()).isEqualTo("EDI_PARTY_NAME: 0x3008a1060c0454657374");

        // check if other name related methods return null when the name type is EDI_PARTY_NAME
        assertThat(generalName.getOtherNameTypeId()).isNull();
        assertThat(generalName.getOtherNameValueAsBytes()).isNull();
        assertThat(generalName.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testUniformResourceIdentifier() throws Exception {
        GeneralName generalName = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier, "http://test.example.com"));
        assertThat(generalName.getNameType()).isEqualTo(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        // 16 17 687474703a2f2f746573742e6578616d706c652e636f6d -- IA5STRING "http://test.example.com"
        assertThat(Hex.toHexString(generalName.getNameValueAsBytes()))
                .isEqualTo("1617687474703a2f2f746573742e6578616d706c652e636f6d");
        assertThat(generalName.getNameValueAsString())
                .isEqualTo("http://test.example.com");
        assertThat(generalName.toString()).isEqualTo("UNIFORM_RESOURCE_IDENTIFIER: http://test.example.com");

        // check if other name related methods return null when the name type is UNIFORM_RESOURCE_IDENTIFIER
        assertThat(generalName.getOtherNameTypeId()).isNull();
        assertThat(generalName.getOtherNameValueAsBytes()).isNull();
        assertThat(generalName.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testIPAddress() throws Exception {
        GeneralName generalNameIPv4_1 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "192.0.2.0"));
        assertThat(generalNameIPv4_1.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 04 c0000200 -- OCTET STRING 192, 0, 2, 0
        assertThat(Hex.toHexString(generalNameIPv4_1.getNameValueAsBytes()))
                .isEqualTo("0404c0000200");
        assertThat(generalNameIPv4_1.getNameValueAsString()).isEqualTo("192.0.2.0");
        assertThat(generalNameIPv4_1.toString()).isEqualTo("IP_ADDRESS: 192.0.2.0");

        GeneralName generalNameIPv4_2 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "192.0.2.1"));
        assertThat(generalNameIPv4_2.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 04 c0000201 -- OCTET STRING 192, 0, 2, 1
        assertThat(Hex.toHexString(generalNameIPv4_2.getNameValueAsBytes()))
                .isEqualTo("0404c0000201");
        assertThat(generalNameIPv4_2.getNameValueAsString()).isEqualTo("192.0.2.1");
        assertThat(generalNameIPv4_2.toString()).isEqualTo("IP_ADDRESS: 192.0.2.1");

        GeneralName generalNameIPv4_3 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "192.0.2.0/255.255.255.0"));
        assertThat(generalNameIPv4_3.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 08 c0000200ffffff00 -- OCTET STRING 192, 0, 2, 0, 255, 255, 255, 0
        assertThat(Hex.toHexString(generalNameIPv4_3.getNameValueAsBytes()))
                .isEqualTo("0408c0000200ffffff00");
        assertThat(generalNameIPv4_3.getNameValueAsString()).isEqualTo("192.0.2.0/255.255.255.0");
        assertThat(generalNameIPv4_3.toString()).isEqualTo("IP_ADDRESS: 192.0.2.0/255.255.255.0");

        GeneralName generalNameIPv4_4 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "192.0.2.0/255.255.255.128"));
        assertThat(generalNameIPv4_4.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 08 c0000200ffffff80 -- OCTET STRING 192, 0, 2, 0, 255, 255, 255, 128
        assertThat(Hex.toHexString(generalNameIPv4_4.getNameValueAsBytes()))
                .isEqualTo("0408c0000200ffffff80");
        assertThat(generalNameIPv4_4.getNameValueAsString()).isEqualTo("192.0.2.0/255.255.255.128");
        assertThat(generalNameIPv4_4.toString()).isEqualTo("IP_ADDRESS: 192.0.2.0/255.255.255.128");

        GeneralName generalNameIPv4_5 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "192.0.2.0/255.255.255.192"));
        assertThat(generalNameIPv4_5.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 08 c0000200ffffffc0 --  OCTET STRING 192, 0, 2, 0, 255, 255, 255, 192
        assertThat(Hex.toHexString(generalNameIPv4_5.getNameValueAsBytes()))
                .isEqualTo("0408c0000200ffffffc0");
        assertThat(generalNameIPv4_5.getNameValueAsString()).isEqualTo("192.0.2.0/255.255.255.192");
        assertThat(generalNameIPv4_5.toString()).isEqualTo("IP_ADDRESS: 192.0.2.0/255.255.255.192");

        GeneralName generalNameIPv6_1 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "2001:db8:0:0:0:0:0:0"));
        assertThat(generalNameIPv6_1.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 10 20010db8000000000000000000000000 -- OCTET STRING [HEX DUMP]: 20010db8000000000000000000000000
        assertThat(Hex.toHexString(generalNameIPv6_1.getNameValueAsBytes()))
                .isEqualTo("041020010db8000000000000000000000000");
        assertThat(generalNameIPv6_1.getNameValueAsString()).isEqualTo("2001:db8:0:0:0:0:0:0");
        assertThat(generalNameIPv6_1.toString()).isEqualTo("IP_ADDRESS: 2001:db8:0:0:0:0:0:0");

        GeneralName generalNameIPv6_2 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "2001:db8:0:0:0:0:0:1"));
        assertThat(generalNameIPv6_2.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 10 20010db8000000000000000000000001 -- OCTET STRING [HEX DUMP]: 20010db8000000000000000000000001
        assertThat(Hex.toHexString(generalNameIPv6_2.getNameValueAsBytes()))
                .isEqualTo("041020010db8000000000000000000000001");
        assertThat(generalNameIPv6_2.getNameValueAsString()).isEqualTo("2001:db8:0:0:0:0:0:1");
        assertThat(generalNameIPv6_2.toString()).isEqualTo("IP_ADDRESS: 2001:db8:0:0:0:0:0:1");

        GeneralName generalNameIPv6_3 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "2001:db8:0:0:0:0:0:0/32"));
        assertThat(generalNameIPv6_3.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 20 20010db8000000000000000000000000ffffffff000000000000000000000000
        //     -- OCTET STRING [HEX DUMP]: 20010db8000000000000000000000000ffffffff000000000000000000000000
        assertThat(Hex.toHexString(generalNameIPv6_3.getNameValueAsBytes()))
                .isEqualTo("042020010db8000000000000000000000000ffffffff000000000000000000000000");
        assertThat(generalNameIPv6_3.getNameValueAsString()).isEqualTo("2001:db8:0:0:0:0:0:0/32");
        assertThat(generalNameIPv6_3.toString()).isEqualTo("IP_ADDRESS: 2001:db8:0:0:0:0:0:0/32");

        GeneralName generalNameIPv6_4 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "2001:db8:0:0:0:0:0:0/33"));
        assertThat(generalNameIPv6_4.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 20 20010db8000000000000000000000000ffffffff800000000000000000000000
        //     -- OCTET STRING [HEX DUMP]: 20010db8000000000000000000000000ffffffff800000000000000000000000
        assertThat(Hex.toHexString(generalNameIPv6_4.getNameValueAsBytes()))
                .isEqualTo("042020010db8000000000000000000000000ffffffff800000000000000000000000");
        assertThat(generalNameIPv6_4.getNameValueAsString()).isEqualTo("2001:db8:0:0:0:0:0:0/33");
        assertThat(generalNameIPv6_4.toString()).isEqualTo("IP_ADDRESS: 2001:db8:0:0:0:0:0:0/33");

        GeneralName generalNameIPv6_5 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.iPAddress, "2001:db8:0:0:0:0:0:0/34"));
        assertThat(generalNameIPv6_5.getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        // 04 20 20010db8000000000000000000000000ffffffffc00000000000000000000000
        //     -- OCTET STRING [HEX DUMP]: 20010db8000000000000000000000000ffffffffc00000000000000000000000
        assertThat(Hex.toHexString(generalNameIPv6_5.getNameValueAsBytes()))
                .isEqualTo("042020010db8000000000000000000000000ffffffffc00000000000000000000000");
        assertThat(generalNameIPv6_5.getNameValueAsString()).isEqualTo("2001:db8:0:0:0:0:0:0/34");
        assertThat(generalNameIPv6_5.toString()).isEqualTo("IP_ADDRESS: 2001:db8:0:0:0:0:0:0/34");

        // check if other name related methods return null when the name type is IP_ADDRESS
        assertThat(generalNameIPv4_1.getOtherNameTypeId()).isNull();
        assertThat(generalNameIPv4_1.getOtherNameValueAsBytes()).isNull();
        assertThat(generalNameIPv4_1.getOtherNameValueAsString()).isNull();
        assertThat(generalNameIPv6_1.getOtherNameTypeId()).isNull();
        assertThat(generalNameIPv6_1.getOtherNameValueAsBytes()).isNull();
        assertThat(generalNameIPv6_1.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testRegisteredId() throws Exception {
        // 2.5.4.3 is the OID for CN
        GeneralName generalName1 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.registeredID, "2.5.4.3"));
        assertThat(generalName1.getNameType()).isEqualTo(GeneralNameType.REGISTERED_ID);
        // 06 03 550403 -- OBJECT IDENTIFIER 2.5.4.3
        assertThat(Hex.toHexString(generalName1.getNameValueAsBytes())).isEqualTo("0603550403");
        assertThat(generalName1.getNameValueAsString()).isEqualTo("2.5.4.3");
        assertThat(generalName1.toString()).isEqualTo("REGISTERED_ID: 2.5.4.3");

        // 0.9.2342.19200300.100.1.1 is the OID for UID
        GeneralName generalName2 = new GeneralName(new org.bouncycastle.asn1.x509.GeneralName(
                org.bouncycastle.asn1.x509.GeneralName.registeredID, "0.9.2342.19200300.100.1.1"));
        assertThat(generalName2.getNameType()).isEqualTo(GeneralNameType.REGISTERED_ID);
        // 06 0a 0992268993f22C640101 -- OBJECT IDENTIFIER 0.9.2342.19200300.100.1.1
        assertThat(Hex.toHexString(generalName2.getNameValueAsBytes())).isEqualTo("060a0992268993f22c640101");
        assertThat(generalName2.getNameValueAsString()).isEqualTo("0.9.2342.19200300.100.1.1");
        assertThat(generalName2.toString()).isEqualTo("REGISTERED_ID: 0.9.2342.19200300.100.1.1");

        // check if other name related methods return null when the name type is REGISTERED_ID
        assertThat(generalName1.getOtherNameTypeId()).isNull();
        assertThat(generalName1.getOtherNameValueAsBytes()).isNull();
        assertThat(generalName1.getOtherNameValueAsString()).isNull();
    }

    @Test
    public void testInvalidArgument() throws Exception {
        // check behavior when passing null
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new GeneralName(null));
    }
}
