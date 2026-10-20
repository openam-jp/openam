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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.testng.annotations.Test;

public class BouncyCastleUtilsTest {

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

    // Client certificate generated using OpenSSL with the following extensions:
    //
    // X509v3 Authority Key Identifier:
    //     0A:F9:CD:C8:6C:B7:FC:A7:F9:30:DF:F2:F1:1A:FA:DE:F4:95:ED:45
    // X509v3 Subject Key Identifier:
    //     0F:FC:FC:03:1A:F2:54:74:F7:5D:FB:BE:E6:7B:CB:0E:BA:8F:77:82
    // X509v3 Key Usage:
    //     Digital Signature
    // X509v3 Subject Alternative Name:
    //     othername: UPN::test@example.com
    //     email:test@example.com
    //     DNS:test.example.com
    //     DirName:/C=JP/O=Company/CN=Example
    //     URI:http://test.example.com
    //     IP Address:192.0.2.1
    //     Registered ID:commonName
    // X509v3 Basic Constraints: critical
    //     CA:FALSE
    // X509v3 Extended Key Usage:
    //     TLS Web Client Authentication
    // X509v3 CRL Distribution Points:
    //     Full Name:
    //       URI:https://example.com/test1.crl
    //     Full Name:
    //       URI:https://example.com/test2.crl
    private static final String CLIENT_CERT = "-----BEGIN CERTIFICATE-----\n"
            + "MIIGzDCCBLSgAwIBAgIUHbpsfiec26waBhVd9IKuC1ttz4QwDQYJKoZIhvcNAQEL\n"
            + "BQAwYjELMAkGA1UEBhMCSlAxDTALBgNVBAgMBFRlc3QxDTALBgNVBAcMBFRlc3Qx\n"
            + "DTALBgNVBAoMBFRlc3QxDTALBgNVBAsMBFRlc3QxFzAVBgNVBAMMDmNhLmV4YW1w\n"
            + "bGUuY29tMB4XDTI0MTEyNTEwMjI1NFoXDTM0MTEyMzEwMjI1NFowZDELMAkGA1UE\n"
            + "BhMCSlAxDTALBgNVBAgMBFRlc3QxDTALBgNVBAcMBFRlc3QxDTALBgNVBAoMBFRl\n"
            + "c3QxDTALBgNVBAsMBFRlc3QxGTAXBgNVBAMMEHRlc3RAZXhhbXBsZS5jb20wggIi\n"
            + "MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCzLT9uoxjEuymwEjvwgla7UUxD\n"
            + "yuqQZMf30D+Pi/HgIggs1l80Qwpvik2V3Fx29QoWNYKb7IfLMKECHFNDSzgycheD\n"
            + "5zYeliYtB3KKU8LH7EFItZWs5tR0Is1iSXqzydfqUjQdWTb61zGOPfxaVG47nZGQ\n"
            + "JCDXnLkdntkcXPHcO95YvOsEUZJY+OrNpvdmChPbj+zcVrifZkRtcRnRifeLOkru\n"
            + "tkdzaSbZKINxZm0VK0/KNZfis6j8SGSsJPZ1J7Ab07QlTdLm3Sb4F8OZZP1gt1fq\n"
            + "a2sp5DO6uc/m+30Dc2YIK6YNvSFZpq4gIIdoeu6Y+62CMzrJOFECQTeWjxzB4LzD\n"
            + "R5/Idcs1J5QE9gJOy4AVbHCCgOTp77dtT6UuYBwvrI3icsUjla0kwthX+O1kpZ/a\n"
            + "MANUHiQYTFssho4YQHSmn4exKhd7+h0H/G4wWUc5cythanhWYCwDpdi3Sub9PqNC\n"
            + "r/gKKU6ZDfDECgaITYlzUXic6uEWM7kqpX5ibc9xxBtrOZskhfJw3h4FcbEOlYg8\n"
            + "y6EKbHGKemoK6rg2LmrOZSK23onfYChW1mGWPoU5MTlPowBR0n5QJ6yv3gsGZja8\n"
            + "mWJvJNDh/TVTLI3DGdncddMSVT+nKzE/5B/YCdxbg9ANwh2a12SQTiRudvaObtu+\n"
            + "IrfRugMz52NfZsORpwIDAQABo4IBdjCCAXIwHwYDVR0jBBgwFoAUCvnNyGy3/Kf5\n"
            + "MN/y8Rr63vSV7UUwHQYDVR0OBBYEFA/8/AMa8lR09137vuZ7yw66j3eCMAsGA1Ud\n"
            + "DwQEAwIHgDCBqgYDVR0RBIGiMIGfoCAGCisGAQQBgjcUAgOgEgwQdGVzdEBleGFt\n"
            + "cGxlLmNvbYEQdGVzdEBleGFtcGxlLmNvbYIQdGVzdC5leGFtcGxlLmNvbaQzMDEx\n"
            + "CzAJBgNVBAYTAkpQMRAwDgYDVQQKDAdDb21wYW55MRAwDgYDVQQDDAdFeGFtcGxl\n"
            + "hhdodHRwOi8vdGVzdC5leGFtcGxlLmNvbYcEwAACAYgDVQQDMAwGA1UdEwEB/wQC\n"
            + "MAAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwUwYDVR0fBEwwSjAjoCGgH4YdaHR0cHM6\n"
            + "Ly9leGFtcGxlLmNvbS90ZXN0MS5jcmwwI6AhoB+GHWh0dHBzOi8vZXhhbXBsZS5j\n"
            + "b20vdGVzdDIuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQCHSE7kEC+P1fG5h+dEdEMT\n"
            + "UR8ALiJ8OUSkdqJxOdFvbLTcjvcDmbEn8lxLcKG1d+ATtO+uSdhXydiKSiXJCdog\n"
            + "6QGYPqj1SP4c+hbgT8OtNwCzrykYN5t19lO8vP/3FVZVnHQbT6QOt3SouzjGCPrw\n"
            + "RFqnEysvF2WkKAOYecSjpHlJEZr8mTypmmygrTNOiMOpCkeV5s/kQSkgm9K2/BXF\n"
            + "axAuT8+YVseZoj+EFTQ8Kc1bCISBDKLe4WFle5o2oY5NWMptRIjrbDisYiXypsuf\n"
            + "deyVRobzGoVevTO5e28x5SOo8MpiJZj2wJwlbNhxNvm/YltaCp/s/xaVyVWx+GqE\n"
            + "A+7RPAfiB8ysRzoNVBIRq8tqtAjR4zvFG/22owjtYyd7SKgzRe84v/qzxtdrdgxC\n"
            + "IRQDOLQsXfPum/6CB8aw7P/2k6I/Mv5j36fIQMe530ilX96QcjV0R8kX3wtbx3vY\n"
            + "ds3m4X5YxZMN4//sjYHzbKhSE//xmYXmH6KqPmzVehVE69CVH1xMhRmLz/4dmqx3\n"
            + "ybKvsBkMdkGDIlb0fKgoIcA7jwkr0HX8E6L4ZtORR9kuMNX4Og4BCzIIW3fI1wsR\n"
            + "olCPHfD4eLBXzbdTRXaW7U9GOKOO40CHb1U3Lw0QblCV3XiAIs0nLzAWOfZO3EnQ\n"
            + "BNQQJbzNkBOFHiCR10bcfA==\n"
            + "-----END CERTIFICATE-----";

    // Client certificate generated using OpenSSL without any extensions.
    private static final String CLIENT_CERT_NO_EXTS = "-----BEGIN CERTIFICATE-----\n"
            + "MIIFTTCCAzUCFD7PQFslTznsGAFEB9DcS388+XdxMA0GCSqGSIb3DQEBCwUAMGIx\n"
            + "CzAJBgNVBAYTAkpQMQ0wCwYDVQQIDARUZXN0MQ0wCwYDVQQHDARUZXN0MQ0wCwYD\n"
            + "VQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MRcwFQYDVQQDDA5jYS5leGFtcGxlLmNv\n"
            + "bTAeFw0yNDExMTgwNzQ0NDVaFw0zNDExMTYwNzQ0NDVaMGQxCzAJBgNVBAYTAkpQ\n"
            + "MQ0wCwYDVQQIDARUZXN0MQ0wCwYDVQQHDARUZXN0MQ0wCwYDVQQKDARUZXN0MQ0w\n"
            + "CwYDVQQLDARUZXN0MRkwFwYDVQQDDBB0ZXN0QGV4YW1wbGUuY29tMIICIjANBgkq\n"
            + "hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkwu5ElE/qkuaEd1raB9xamn1Pb1+d+kK\n"
            + "mfqlEH2T1hqe1ci1k9Zyprt7JzV7iD0LO4MCfuKjInwWrPOBL4IqGixAkWSINWmN\n"
            + "q938zze2iqGbA688sAfvrn7wPn/OLEcIK5aNtmsoqZ9d33SCqfGA+hfDVdGRYu85\n"
            + "rGrVeladJ7bULFHExZKgN8tI38tRxc7hH27NDgT6OzEKcJVN6qCvzScbatRfWFTW\n"
            + "RwbyXy5AkeRG4D6hQOHYV0tCZnqegJsAunAUde3+NpfH+tKHfhVaqTTRA1QLYQ3M\n"
            + "9KBu3NUV+lzUbh2xwEiMvujxPl4VUkm/bpfoboGy7fknbk7GMMB85dHp+hnI+4kf\n"
            + "NXgHW7Lj1lNHja21GfRznpx1oQRHfOh+vf5N7riRG2zcPV48v8Bnxp2j0dt1LyzI\n"
            + "Xh/dwf3QesCcbuaHdPz1DrYzy716+8jndnzKXxXmtxYaRqfU3XZAMDTJnm6rD3qP\n"
            + "s+YV0LbGlpfLVXjHcGQ67c0egQDGbQ1by8UJPFNW5CCNrSkPPAuNRg82pH+4tNa0\n"
            + "f6BVvG7rBClsDyp7pM+/Uk8ytZkShBt+iPOowOhL4aptILk7hHJra3ezV8LxJI6d\n"
            + "geYHMVd7vcwkr7g/exutGhCrMzuvBrZflT/Ir2tFcJ28OGhkNFyK98yL44UGDHk4\n"
            + "PYjUpG9gkU8CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAP9iFoo3SQITTES/gG3e+\n"
            + "lEeTNmR2+lHC7mdKxTrhjqduPTizRmlz7n3fdOqQwlcxP+ygC0bfdlsKiWbnqY3S\n"
            + "sRLh9WgPyYWecYGYmQoohprChJWwZP5DGg7GFYxKrewOIRWmbDwA5H0/Qty4J9gR\n"
            + "sxo9pSU4s0nwVAwi3dIPO2/bUFw5Pk3jN181I1rCSGwTH0uI6lnseHXMIjBzdLmU\n"
            + "svZrea9F4MgON3z6H1Sz0cn/BohK7VdEqMn5Y8i9EHIwmc3m0+KLc65fvwhZKeGY\n"
            + "s/AOLHeVpP3ga3I6Xe0cc6ie6NiS3Oo1TrIVBSkOVMb/Mh3GuE1i3rNGw1StwAmd\n"
            + "bw4AY4H1/vdYCsyVcXW3UyYAgqP2Zadz2wxK1w8+S+unqPFBj27voaJmLWX12RFT\n"
            + "9A1F2/yfqonmGTQsamGuAKg2UlGb+kR9QbdzDLt7smU/pI5Sk6+vpH9Ojttr9Tn7\n"
            + "tE4EUSV5QW82MClwWVzXq3wIgsrEBcGQs4J6bPgzzI011f6HhE10hNwbj3dt3jPQ\n"
            + "xlf7PDVQdIZ0ewWu+rcLS4V36KpKgf1ewJZOQtGmp9eOHkPrvOC9fW9cXHZbEcS/\n"
            + "1LltwaMAawtwPVkkXxaq3+DMr2yM72VdlFvZ1G8Y3xHvdiK9Qrg72D6C2Xo7D4iH\n"
            + "bF3rk07ohOjtjSSaBjZdOIU=\n"
            + "-----END CERTIFICATE-----";

    // CRL generated using OpenSSL with the following extensions:
    //
    // X509v3 Issuing Distribution Point: critical
    //     Full Name:
    //       URI:https://example.com/test1.crl
    //       URI:https://example.com/test2.crl
    // X509v3 CRL Number:
    //     0
    private static final String CRL = "-----BEGIN X509 CRL-----\n"
            + "MIIDNTCCAR0CAQEwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCSlAxDTALBgNV\n"
            + "BAgMBFRlc3QxDTALBgNVBAcMBFRlc3QxDTALBgNVBAoMBFRlc3QxDTALBgNVBAsM\n"
            + "BFRlc3QxFzAVBgNVBAMMDmNhLmV4YW1wbGUuY29tFw0yNDExMTgwNzE4MTBaFw0y\n"
            + "NDExMTgwNzE5MTBaMCcwJQIUJ2m3oio9IaZX953e+kQVe2Tw3BsXDTI0MTExODA3\n"
            + "MTgxMFqgXjBcME4GA1UdHAEB/wREMEKgQKA+hh1odHRwczovL2V4YW1wbGUuY29t\n"
            + "L3Rlc3QxLmNybIYdaHR0cHM6Ly9leGFtcGxlLmNvbS90ZXN0Mi5jcmwwCgYDVR0U\n"
            + "BAMCAQAwDQYJKoZIhvcNAQELBQADggIBAG5McBmCTrRe7aPuYi0DM+lErzcOijQ+\n"
            + "SKdn0g4Mt4fHvnmVsUXaJYSKykUU+IunNA2VQF3hWYoHSI4Fnqzr1c7ZxijsBMAG\n"
            + "wRsx+Lq8j4XX/GRZ9SFmYvfc5wxQbpB9Hi7B56JcfpLbohga+JC3rYgPP62SWmH6\n"
            + "aQY6nofKFQuaTFLUIwipbqdq+Ex8eKgZQLwiPyzZwmnhDRyyzHl9MMgUi+VDN74z\n"
            + "nd/Q3qgPeMQJUlE9x17HBDkOxreeU+KyMZuhR4Cz3CIyRDbltOs0VDo3bbIg6fhd\n"
            + "0qNoXfwRS1Yl0OcAEUEDLa38irxYHGROO21TynTXENQrHJ8lw73Yvo819JTgZYhz\n"
            + "i1SvHZhgTVpBrvmuwlk7HPsAE4JAZ20wihlORWComSKNCwLDyhPx/AlbSOH4IVuq\n"
            + "0gzZcFsnmiXiHRt6V0EZycEYhobpXEAjnBOaTjuY34ZF0UFBSSaJ2GB1vYw2RLoG\n"
            + "dgXG9+uJ9pueA0gynrBlpCsardKAeE2in3VrhZjO6eHJVaZC1AZ4jN8kltr4Rm5Q\n"
            + "/vphJEElfCKuWxrmlLT/41MZ77epa01okxKGLhZdutOBlhwFm+aZMjAZf5bQcZKa\n"
            + "8bKaOnoGF7lBAeu8wM1i7Es2OvVybUtpJgTfNEfST0oPBaofeX1z/HF5LBKqrGDg\n"
            + "SBfQfA8VoDWn\n"
            + "-----END X509 CRL-----";

    // CRL generated using OpenSSL without any extensions.
    private static final String CRL_NO_EXTS = "-----BEGIN X509 CRL-----\n"
            + "MIIC0TCBujANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJKUDENMAsGA1UECAwE\n"
            + "VGVzdDENMAsGA1UEBwwEVGVzdDENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVz\n"
            + "dDEXMBUGA1UEAwwOY2EuZXhhbXBsZS5jb20XDTI0MTExODA3NDQ0NloXDTI0MTEx\n"
            + "ODA3NDU0NlowJzAlAhQ+z0BbJU857BgBRAfQ3Et/PPl3cRcNMjQxMTE4MDc0NDQ2\n"
            + "WjANBgkqhkiG9w0BAQsFAAOCAgEAjC9t/Jz3SEfwCwNUk8o0s56GRwfHnVC7uCnp\n"
            + "C+ndHrXUHCqfWp4d8qZxdUeRoZj0rImC8Y2aqCzDbphrnoZm6gGfe/wAHChmlrv/\n"
            + "PdCL+pp9pK60w4lLNCgQ7jBq3KoVQcqPSk5/toC+7+8G/TeqSjCEfb6Fjz3+OazT\n"
            + "eZ+GFNMTjYxCQvaMY9Eo7xwni9qzrcUM5QjEeAIA/SIr5AI47KjEy0m2AEI9bGj2\n"
            + "DLotrmy1PoMNAWWttf8X6UZTQOzu/u4dr/3bALHv6LrRvTM91iPWc/GV9j9tWdsC\n"
            + "hjhqiLJg1T2+pDOg0+HQIFIlyWZiC9ssfU/Zt0EzW05/6ZGI/0ePVk2FuVcXqqZI\n"
            + "eJAhiDrFcCLOWxtNRrqPlt1fsvk3T39QhXRKd4biH1g2m+Yt8IQOKgM1AN38wzCW\n"
            + "49HMx8GrS+n2g9aHiHpKBA+tJxT0wx9Xch5VFEFwX5I9G9iHXERyDGoPtYvHxohK\n"
            + "QoLCPO5y1G0AChfY++f4pPAQqw87nQ3q73EvIfHLNzSu50Irpo17vVMl64WpygVf\n"
            + "ttbdMwYkMESinRDKTOHsAw9Rou2YD5EPyPMdtTqIK8JO5Y4ZaNyWrnlOSOUayMEM\n"
            + "xLEJDjXTRWvtHTcFt/D9UN0KZbtEpDIeOq7PU8mfQnjGdf8iJ9hB3/QfHtv6/Vg/\n"
            + "J9SoA3c=\n"
            + "-----END X509 CRL-----";

    @Test
    public void testGetSubjectAlternativeNameAsCollection() throws Exception {
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(CLIENT_CERT.getBytes()));
        Collection<GeneralName> collection =
                BouncyCastleUtils.getSubjectAlternativeNameAsCollection(cert);
        assertThat(collection.size()).isEqualTo(7);

        ArrayList<GeneralName> list = new ArrayList<>(collection);
        assertThat(list.get(0).getNameType()).isEqualTo(GeneralNameType.OTHER_NAME);
        assertThat(list.get(0).getOtherNameTypeId()).isEqualTo("1.3.6.1.4.1.311.20.2.3");
        assertThat(list.get(0).getOtherNameValueAsString()).isEqualTo("test@example.com");

        assertThat(list.get(1).getNameType()).isEqualTo(GeneralNameType.RFC822_NAME);
        assertThat(list.get(1).getNameValueAsString()).isEqualTo("test@example.com");

        assertThat(list.get(2).getNameType()).isEqualTo(GeneralNameType.DNS_NAME);
        assertThat(list.get(2).getNameValueAsString()).isEqualTo("test.example.com");

        assertThat(list.get(3).getNameType()).isEqualTo(GeneralNameType.DIRECTORY_NAME);
        assertThat(list.get(3).getNameValueAsString()).isEqualTo("CN=Example,O=Company,C=JP");

        assertThat(list.get(4).getNameType()).isEqualTo(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        assertThat(list.get(4).getNameValueAsString()).isEqualTo("http://test.example.com");

        assertThat(list.get(5).getNameType()).isEqualTo(GeneralNameType.IP_ADDRESS);
        assertThat(list.get(5).getNameValueAsString()).isEqualTo("192.0.2.1");

        assertThat(list.get(6).getNameType()).isEqualTo(GeneralNameType.REGISTERED_ID);
        assertThat(list.get(6).getNameValueAsString()).isEqualTo("2.5.4.3");

        // check immutability
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> collection.clear());

        X509Certificate certNoExts = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(CLIENT_CERT_NO_EXTS.getBytes()));
        Collection<GeneralName> emptyCollection =
                BouncyCastleUtils.getSubjectAlternativeNameAsCollection(certNoExts);
        assertThat(emptyCollection.isEmpty()).isTrue();

        // check behavior when passing null
        assertThatIllegalArgumentException()
                .isThrownBy(() -> BouncyCastleUtils.getSubjectAlternativeNameAsCollection(null));
    }

    @Test
    public void testGetCRLDistributionPointsFullNamesAsCollection() throws Exception {
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(CLIENT_CERT.getBytes()));
        Collection<GeneralName> collection =
                BouncyCastleUtils.getCRLDistributionPointsFullNamesAsCollection(cert);
        assertThat(collection.size()).isEqualTo(2);

        ArrayList<GeneralName> list = new ArrayList<>(collection);
        assertThat(list.get(0).getNameType()).isEqualTo(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        assertThat(list.get(0).getNameValueAsString()).isEqualTo("https://example.com/test1.crl");

        assertThat(list.get(1).getNameType()).isEqualTo(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        assertThat(list.get(1).getNameValueAsString()).isEqualTo("https://example.com/test2.crl");

        // check immutability
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> collection.clear());

        X509Certificate certNoExts = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(CLIENT_CERT_NO_EXTS.getBytes()));
        Collection<GeneralName> emptyCollection =
                BouncyCastleUtils.getCRLDistributionPointsFullNamesAsCollection(certNoExts);
        assertThat(emptyCollection.isEmpty()).isTrue();

        // check behavior when passing null
        assertThatIllegalArgumentException()
                .isThrownBy(() -> BouncyCastleUtils.getCRLDistributionPointsFullNamesAsCollection(null));
    }

    @Test
    public void testGetIssuingDistributionPointFullNameAsCollection() throws Exception {
        X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
                .generateCRL(new ByteArrayInputStream(CRL.getBytes()));
        Collection<GeneralName> collection =
                BouncyCastleUtils.getIssuingDistributionPointFullNameAsCollection(crl);
        assertThat(collection.size()).isEqualTo(2);

        ArrayList<GeneralName> list = new ArrayList<>(collection);
        assertThat(list.get(0).getNameType()).isEqualTo(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        assertThat(list.get(0).getNameValueAsString()).isEqualTo("https://example.com/test1.crl");

        assertThat(list.get(1).getNameType()).isEqualTo(GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER);
        assertThat(list.get(1).getNameValueAsString()).isEqualTo("https://example.com/test2.crl");

        // check immutability
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> collection.clear());

        X509CRL crlNoExts = (X509CRL) CertificateFactory.getInstance("X.509")
                .generateCRL(new ByteArrayInputStream(CRL_NO_EXTS.getBytes()));
        Collection<GeneralName> emptyCollection =
                BouncyCastleUtils.getIssuingDistributionPointFullNameAsCollection(crlNoExts);
        assertThat(emptyCollection.isEmpty()).isTrue();

        // check behavior when passing null
        assertThatIllegalArgumentException()
                .isThrownBy(() -> BouncyCastleUtils.getIssuingDistributionPointFullNameAsCollection(null));
    }
}
