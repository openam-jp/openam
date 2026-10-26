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

import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import com.sun.identity.shared.debug.Debug;

/**
 * Utility class for handling X.509 certificates and CRLs using the Bouncy Castle library.
 */
public final class BouncyCastleUtils {

    private static final Debug DEBUG = Debug.getInstance("amBouncyCastleUtils");

    /**
     * Gets an immutable {@code Collection} representing Subject Alternative Name extension
     * (OID = 2.5.29.17) from the provided X.509 certificate.
     * <p>
     * The ASN.1 definition of the Subject Alternative Name extension is:
     * <pre>
     * SubjectAltName ::= GeneralNames
     *
     * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
     *
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
     * If the certificate does not contain the Subject Alternative Name extension, an empty
     * {@code Collection} is returned.
     * Otherwise, a {@code Collection} containing {@code GeneralName} objects representing each
     * GeneralName in the extension is returned.
     *
     * @param certificate the X.509 certificate from which to extract the Subject Alternative Name
     *         extension. Must not be {@code null}.
     * @return an immutable {@code Collection} of Subject Alternative Name extension if the extension
     *         is present, or an empty {@code Collection} if the extension is not present.
     * @throws IllegalArgumentException if the {@code certificate} argument is {@code null}.
     * @throws CertificateParsingException if an error occurs while parsing the certificate or the
     *         extension.
     */
    public static Collection<jp.co.osstech.openam.shared.cert.GeneralName>
            getSubjectAlternativeNameAsCollection(X509Certificate certificate)
            throws IllegalArgumentException, CertificateParsingException {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must not be null");
        }
        DEBUG.message("getSubjectAlternativeNameAsCollection: certificate = {}", certificate);
        GeneralNames generalNames = getSubjectAlternativeName(certificate);
        if (generalNames == null) {
            return Collections.emptySet();
        }
        try {
            return convertGeneralNamesToCollection(generalNames);
        } catch (Exception e) {
            throw new CertificateParsingException("Failed to parse Subject Alternative Name extension", e);
        }
    }

    /**
     * Gets an immutable {@code Collection} representing full names of DistributionPointNames included
     * in CRL Distribution Points extension (OID = 2.5.29.31) from the provided X.509 certificate.
     * <p>
     * The ASN.1 definition of the CRL Distribution Points extension is:
     * <pre>
     * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
     *
     * DistributionPoint ::= SEQUENCE {
     *      distributionPoint       [0]     DistributionPointName OPTIONAL,
     *      reasons                 [1]     ReasonFlags OPTIONAL,
     *      cRLIssuer               [2]     GeneralNames OPTIONAL }
     *
     * DistributionPointName ::= CHOICE {
     *      fullName                [0]     GeneralNames,
     *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
     * </pre>
     * If the certificate does not contain the CRL Distribution Points extension or the extension
     * does not contain full name, an empty {@code Collection} is returned.
     * Otherwise, a {@code Collection} containing {@code GeneralName} objects representing each
     * GeneralName in GeneralNames (fullName) included in the extension is returned.
     *
     * @param certificate the X.509 certificate from which to extract the CRL Distribution Points
     *         extension. Must not be {@code null}.
     * @return an immutable {@code Collection} of full name in distribution point included in
     *         CRL Distribution Points extension if the extension is present, or an empty
     *         {@code Collection} if the extension is not present or the extension contains no
     *         full names.
     * @throws IllegalArgumentException if the {@code certificate} argument is {@code null}.
     * @throws CertificateParsingException if an error occurs while parsing the certificate or the
     *         extension.
     */
    public static Collection<jp.co.osstech.openam.shared.cert.GeneralName>
            getCRLDistributionPointsFullNamesAsCollection(X509Certificate certificate)
            throws IllegalArgumentException, CertificateParsingException {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must not be null");
        }
        DEBUG.message("getCRLDistributionPointsFullNamesAsCollection: certificate = {}", certificate);
        CRLDistPoint crlDistPoint = getCRLDistributionPoints(certificate);
        if (crlDistPoint == null) {
            return Collections.emptySet();
        }
        try {
            DistributionPoint[] distPoints = crlDistPoint.getDistributionPoints();
            if (distPoints == null || distPoints.length == 0) {
                DEBUG.message("getCRLDistributionPointsFullNamesAsCollection: distPoints is null or empty");
                return Collections.emptySet();
            }
            Collection<jp.co.osstech.openam.shared.cert.GeneralName> result = new ArrayList<>();
            for (DistributionPoint distPoint : distPoints) {
                DistributionPointName distPointName = distPoint.getDistributionPoint();
                if (distPointName == null) {
                    DEBUG.message("getCRLDistributionPointsFullNamesAsCollection: "
                            + "Distribution point name is not contained");
                    continue;
                }
                result.addAll(convertDistPointFullNameToCollection(distPointName));
            }
            return Collections.unmodifiableCollection(result);
        } catch (Exception e) {
            throw new CertificateParsingException("Failed to parse CRL Distribution Points extension", e);
        }
    }

    /**
     * Gets an immutable {@code Collection} representing full name of DistributionPointName included
     * in Issuing Distribution Point extension (OID = 2.5.29.28) from the provided X.509 CRL.
     * <p>
     * The ASN.1 definition of the Issuing Distribution Point extension is:
     * <pre>
     * IssuingDistributionPoint ::= SEQUENCE {
     *      distributionPoint          [0] DistributionPointName OPTIONAL,
     *      onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
     *      onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
     *      onlySomeReasons            [3] ReasonFlags OPTIONAL,
     *      indirectCRL                [4] BOOLEAN DEFAULT FALSE,
     *      onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
     *
     *      -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
     *      -- and onlyContainsAttributeCerts may be set to TRUE.
     *
     * DistributionPointName ::= CHOICE {
     *      fullName                [0]     GeneralNames,
     *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
     * </pre>
     * If the CRL does not contain the Issuing Distribution Point extension or the extension
     * does not contain full name, an empty {@code Collection} is returned.
     * Otherwise, a {@code Collection} containing {@code GeneralName} objects representing each
     * GeneralName in GeneralNames (fullName) included in the extension is returned.
     *
     * @param crl the X.509 CRL from which to extract the Issuing Distribution Point
     *            extension. Must not be {@code null}.
     * @return an immutable {@code Collection} of full name in distribution point included in
     *         Issuing Distribution Point extension if the extension is present, or an empty
     *         {@code Collection} if the extension is not present or the extension contains no
     *         full names.
     * @throws IllegalArgumentException if the {@code crl} argument is {@code null}.
     * @throws CRLException if an error occurs while parsing the CRL or the extension.
     */
    public static Collection<jp.co.osstech.openam.shared.cert.GeneralName>
            getIssuingDistributionPointFullNameAsCollection(X509CRL crl)
            throws IllegalArgumentException, CRLException {
        if (crl == null) {
            throw new IllegalArgumentException("crl must not be null");
        }
        DEBUG.message("getIssuingDistributionPointFullNameAsCollection: crl = {}", crl);
        IssuingDistributionPoint issuingDistPoint = getIssuingDistributionPoint(crl);
        if (issuingDistPoint == null) {
            return Collections.emptySet();
        }
        try {
            DistributionPointName distPointName = issuingDistPoint.getDistributionPoint();
            if (distPointName == null) {
                DEBUG.message("getIssuingDistributionPointFullNameAsCollection: "
                        + "Distribution point name is not contained");
                return Collections.emptySet();
            }
            return convertDistPointFullNameToCollection(distPointName);
        } catch (Exception e) {
            throw new CRLException("Failed to parse Issuing Distribution Point extension", e);
        }
    }

    /**
     * Returns whether the provided X.509 CRL declares itself an <em>indirect</em> CRL, that is, a
     * CRL whose entries may have been issued by a CRL issuer other than the issuer of the
     * certificate being checked (RFC 5280 section 5.2.5).
     * <p>
     * The flag is the {@code indirectCRL} field of the Issuing Distribution Point extension
     * (OID = 2.5.29.28), which defaults to FALSE when the field or the extension is absent.
     *
     * @param crl the X.509 CRL to inspect. Must not be {@code null}.
     * @return {@code true} if the CRL carries an Issuing Distribution Point extension whose
     *         {@code indirectCRL} field is set, {@code false} otherwise, including when the
     *         extension is not present.
     * @throws IllegalArgumentException if the {@code crl} argument is {@code null}.
     * @throws CRLException if an error occurs while parsing the CRL or the extension.
     */
    public static boolean isIndirectCRL(X509CRL crl) throws IllegalArgumentException, CRLException {
        if (crl == null) {
            throw new IllegalArgumentException("crl must not be null");
        }
        DEBUG.message("isIndirectCRL: crl = {}", crl);
        IssuingDistributionPoint issuingDistPoint = getIssuingDistributionPoint(crl);
        return issuingDistPoint != null && issuingDistPoint.isIndirectCRL();
    }

    /**
     * Gets the value of the CRL Number extension (OID = 2.5.29.20) of the provided X.509 CRL.
     * <p>
     * The ASN.1 definition of the CRL Number extension is:
     * <pre>
     * CRLNumber ::= INTEGER (0..MAX)
     * </pre>
     * The value is a monotonically increasing sequence number the CRL issuer assigns to each CRL
     * it publishes (RFC 5280 section 5.2.3), which is what lets a caller tell a newer CRL from one
     * that has been superseded.
     *
     * @param crl the X.509 CRL from which to extract the CRL Number extension. Must not be
     *         {@code null}.
     * @return the CRL number, or {@code null} if the extension is not present.
     * @throws IllegalArgumentException if the {@code crl} argument is {@code null}.
     * @throws CRLException if an error occurs while parsing the CRL or the extension.
     */
    public static BigInteger getCRLNumber(X509CRL crl) throws IllegalArgumentException, CRLException {
        if (crl == null) {
            throw new IllegalArgumentException("crl must not be null");
        }
        DEBUG.message("getCRLNumber: crl = {}", crl);
        try {
            // Convert X509CRL to Bouncy Castle's X509CRLHolder
            X509CRLHolder crlHolder = new JcaX509CRLHolder(crl);
            Extension crlNumberExt = crlHolder.getExtension(Extension.cRLNumber);
            if (crlNumberExt == null) {
                DEBUG.message("getCRLNumber: CRL Number extension not found");
                return null;
            }

            // Parse CRLNumber from the CRL Number extension
            return CRLNumber.getInstance(crlNumberExt.getParsedValue()).getCRLNumber();
        } catch (Exception e) {
            throw new CRLException("Failed to parse CRL Number extension", e);
        }
    }

    /**
     * Gets an immutable {@code Collection} representing the cRLIssuer names of every
     * DistributionPoint in the CRL Distribution Points extension (OID = 2.5.29.31) of the provided
     * X.509 certificate.
     * <p>
     * A cRLIssuer names the delegated CRL signer the certificate's issuer authorised to publish
     * CRLs on its behalf; see {@link #getCRLDistributionPointsFullNamesAsCollection} for the ASN.1
     * definition of the extension. The names of every distribution point are returned as one
     * {@code Collection}: the only question asked of them is whether the certificate names a given
     * CRL issuer at all, so which distribution point named it does not change the answer.
     * <p>
     * If the certificate does not contain the CRL Distribution Points extension, or no distribution
     * point in it carries a cRLIssuer, an empty {@code Collection} is returned.
     *
     * @param certificate the X.509 certificate from which to extract the cRLIssuer names. Must not
     *         be {@code null}.
     * @return an immutable {@code Collection} of the cRLIssuer names included in the CRL
     *         Distribution Points extension, or an empty {@code Collection} if the extension is not
     *         present or contains no cRLIssuer.
     * @throws IllegalArgumentException if the {@code certificate} argument is {@code null}.
     * @throws CertificateParsingException if an error occurs while parsing the certificate or the
     *         extension.
     */
    public static Collection<jp.co.osstech.openam.shared.cert.GeneralName>
            getCRLDistributionPointsCRLIssuersAsCollection(X509Certificate certificate)
            throws IllegalArgumentException, CertificateParsingException {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must not be null");
        }
        DEBUG.message("getCRLDistributionPointsCRLIssuersAsCollection: certificate = {}", certificate);
        CRLDistPoint crlDistPoint = getCRLDistributionPoints(certificate);
        if (crlDistPoint == null) {
            return Collections.emptySet();
        }
        try {
            DistributionPoint[] distPoints = crlDistPoint.getDistributionPoints();
            if (distPoints == null || distPoints.length == 0) {
                DEBUG.message("getCRLDistributionPointsCRLIssuersAsCollection: distPoints is null or empty");
                return Collections.emptySet();
            }
            Collection<jp.co.osstech.openam.shared.cert.GeneralName> result = new ArrayList<>();
            for (DistributionPoint distPoint : distPoints) {
                GeneralNames crlIssuer = distPoint.getCRLIssuer();
                if (crlIssuer == null) {
                    DEBUG.message("getCRLDistributionPointsCRLIssuersAsCollection: "
                            + "cRLIssuer is not contained");
                    continue;
                }
                result.addAll(convertGeneralNamesToCollection(crlIssuer));
            }
            return Collections.unmodifiableCollection(result);
        } catch (Exception e) {
            throw new CertificateParsingException("Failed to parse CRL Distribution Points extension", e);
        }
    }

    /**
     * Extracts the Subject Alternative Name extension from the provided X.509 certificate.
     *
     * @param certificate X.509 certificate from which to extract the Subject Alternative Name extension.
     * @return a {@code GeneralNames} object if the extension is present, or {@code null} if the extension
     *         not present.
     * @throws CertificateParsingException if an error occurs while parsing the Subject Alternative
     *         Name extension.
     */
    private static GeneralNames getSubjectAlternativeName(X509Certificate certificate)
            throws CertificateParsingException {
        GeneralNames generalNames;
        try {
            // Convert X509Certificate to Bouncy Castle's X509CertificateHolder
            X509CertificateHolder certHolder = new JcaX509CertificateHolder(certificate);
            Extension subjectAltNameExt = certHolder.getExtension(Extension.subjectAlternativeName);
            if (subjectAltNameExt == null) {
                DEBUG.message("getSubjectAlternativeName: Subject Alternative Name extension not found");
                return null;
            }

            // Parse GeneralNames from the Subject Alternative Name extension
            generalNames = GeneralNames.getInstance(subjectAltNameExt.getParsedValue());
        } catch (Exception e) {
            throw new CertificateParsingException("Failed to parse Subject Alternative Name extension", e);
        }
        if (generalNames == null) {
            throw new CertificateParsingException("Failed to parse Subject Alternative Name extension");
        }
        return generalNames;
    }

    /**
     * Extracts the CRL Distribution Points extension from the provided X.509 certificate.
     *
     * @param certificate X.509 certificate from which to extract the CRL Distribution Points extension.
     * @return a {@code CRLDistPoint} object if the extension is present, or {@code null} if the extension
     *         not present.
     * @throws CertificateParsingException if an error occurs while parsing the CRL Distribution
     *         Points extension.
     */
    private static CRLDistPoint getCRLDistributionPoints(X509Certificate certificate)
            throws CertificateParsingException {
        CRLDistPoint crlDistPoint;
        try {
            // Convert X509Certificate to Bouncy Castle's X509CertificateHolder
            X509CertificateHolder certHolder = new JcaX509CertificateHolder(certificate);
            Extension crlDistPointsExt = certHolder.getExtension(Extension.cRLDistributionPoints);
            if (crlDistPointsExt == null) {
                DEBUG.message("getCRLDistributionPoints: CRL Distribution Points extension not found");
                return null;
            }

            // Parse CRLDistPoint from the CRL Distribution Points extension
            crlDistPoint = CRLDistPoint.getInstance(crlDistPointsExt.getParsedValue());
        } catch (Exception e) {
            throw new CertificateParsingException("Failed to parse CRL Distribution Points extension", e);
        }
        if (crlDistPoint == null) {
            throw new CertificateParsingException("Failed to parse CRL Distribution Points extension");
        }
        return crlDistPoint;
    }

    /**
     * Extracts the Issuing Distribution Point extension from an X.509 CRL.
     *
     * @param crl X.509 CRL from which to extract the Issuing Distribution Point extension.
     * @return an {@code IssuingDistributionPoint} object if the extension is present, or {@code null}
     *         if the extension not present.
     * @throws CRLException if an error occurs while parsing the Issuing Distribution Point extension.
     */
    private static IssuingDistributionPoint getIssuingDistributionPoint(X509CRL crl) throws CRLException {
        IssuingDistributionPoint issuingDistPoint;
        try {
            // Convert X509CRL to Bouncy Castle's X509CRLHolder
            X509CRLHolder crlHolder = new JcaX509CRLHolder(crl);
            Extension issuingDistPointExt = crlHolder.getExtension(Extension.issuingDistributionPoint);
            if (issuingDistPointExt == null) {
                DEBUG.message("getIssuingDistributionPoint: Issuing Distribution Point extension not found");
                return null;
            }

            // Parse IssuingDistributionPoint from the Issuing Distribution Point extension
            issuingDistPoint = IssuingDistributionPoint.getInstance(issuingDistPointExt.getParsedValue());
        } catch (Exception e) {
            throw new CRLException("Failed to parse Issuing Distribution Point extension", e);
        }
        if (issuingDistPoint == null) {
            throw new CRLException("Failed to parse Issuing Distribution Point extension");
        }
        return issuingDistPoint;
    }

    /**
     * Extracts {@code GeneralNames} from a {@code DistributionPointName} with FULL_NAME type and
     * converts them to a {@code Collection} using {@link #convertGeneralNamesToCollection(GeneralNames)}.
     *
     * @param distPointName the {@code DistributionPointName} to convert. Must not be {@code null}.
     * @return a {@code Collection} of {@code GeneralNames} converted from the input, or an empty
     *         {@code Collection} if {@code GeneralNames} is not contained.
     * @throws IllegalStateException if an error occurs while parsing the full name in
     *         the {@code DistributionPointName}.
     */
    private static Collection<jp.co.osstech.openam.shared.cert.GeneralName>
            convertDistPointFullNameToCollection(DistributionPointName distPointName)
            throws IllegalStateException {
        if (distPointName.getType() != DistributionPointName.FULL_NAME || distPointName.getName() == null) {
            DEBUG.message("convertDistPointFullNameToCollection: distPointName type is not fullName "
                    + "or the tagged object it contains is null");
            return Collections.emptyList();
        }

        DEBUG.message("convertDistPointFullNameToCollection: distPointName = {}", distPointName);

        // Extract GeneralNames from the DistributionPointName
        GeneralNames generalNames = GeneralNames.getInstance(distPointName.getName());
        if (generalNames == null) {
            throw new IllegalStateException("Failed to parse full name in distribution point name");
        }
        return convertGeneralNamesToCollection(generalNames);
    }

    /**
     * Converts {@code GeneralNames} object to an immutable {@code Collection} of {@code GeneralName}.
     *
     * @param generalNames the {@code GeneralNames} object to convert. Must not be {@code null}.
     * @return an immutable {@code Collection} of {@code GeneralName}, or an empty {@code Collection}
     *         if the input contains no names.
     */
    private static Collection<jp.co.osstech.openam.shared.cert.GeneralName>
            convertGeneralNamesToCollection(GeneralNames generalNames) {
        GeneralName[] generalNameArray = generalNames.getNames();
        if (generalNameArray == null || generalNameArray.length == 0) {
            return Collections.emptyList();
        }
        Collection<jp.co.osstech.openam.shared.cert.GeneralName> result = new ArrayList<>();
        for (GeneralName generalName : generalNameArray) {
            result.add(new jp.co.osstech.openam.shared.cert.GeneralName(generalName));
        }
        return Collections.unmodifiableCollection(result);
    }
}
