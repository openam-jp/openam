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
 * Copyright 2026 3A Systems, LLC.
 * Portions copyright 2026 OSSTech Corporation
 */
package com.sun.identity.saml.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.security.AccessController;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.forgerock.openam.utils.AMKeyProvider;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import com.sun.identity.saml.common.SAMLServiceManager.SiteEntry;
import com.sun.identity.saml.xmlsig.AMSignatureProvider;
import com.sun.identity.saml.xmlsig.XMLSignatureManager;
import com.sun.identity.saml2.common.SAML2Utils;
import com.sun.identity.security.EncodeAction;
import com.sun.identity.shared.encode.URLEncDec;
import com.sun.identity.shared.xml.XMLUtils;

public class SAMLUtilsTest {

    private static final String ISSUER = "https://idp-a.example.com";
    private static final String ID_ATTRIBUTE = "ID";

    private static final Pattern HIDDEN_INPUT =
            Pattern.compile("<INPUT TYPE=\"HIDDEN\" NAME=\"([^\"<>]*)\" VALUE=\"([^\"<>]*)\">");

    private static final Pattern CHAR_REF = Pattern.compile("&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);");

    /**
     * postYN() only checks host, port and path of the target, so the query string
     * is attacker-influenced and must not be able to close the ACTION attribute.
     */
    @Test
    public void postToTargetEscapesTargetUrlInFormAction() throws Exception {
        String target = "https://sp.example.com/acs?next=\"><script>alert(1)</script><a href=\"";
        StringWriter html = new StringWriter();

        SAMLUtils.postToTarget(null, new PrintWriter(html), Collections.emptyList(), target,
                Collections.emptyMap());

        String out = html.toString();
        assertThat(out).doesNotContain("<script>");
        Matcher action = Pattern.compile("<FORM METHOD=\"POST\" ACTION=\"([^\"<>]*)\">").matcher(out);
        assertThat(action.find()).isTrue();
        assertThat(decode(action.group(1))).isEqualTo(target);
    }

    /**
     * Attribute names and values come verbatim from the partner IdP's assertion, so they are
     * escaped in full: markup must stay inert and an '&' must reach the target unchanged.
     */
    @Test
    public void postToTargetEscapesAttributeNamesAndValues() throws Exception {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("x\"<y", "<script>alert(1)</script>");
        attrs.put("amp", "a&amp;b");
        attrs.put("q", "\" onfocus=\"alert(1)\" autofocus x=\"");
        StringWriter html = new StringWriter();

        SAMLUtils.postToTarget(null, new PrintWriter(html), Collections.emptyList(),
                "https://sp.example.com/acs", attrs);

        String out = html.toString();
        assertThat(out).doesNotContain("<script>");
        assertThat(out).doesNotContain("onfocus=");

        // Every hidden input must parse as exactly one NAME and one VALUE attribute,
        // and decode back to what was posted.
        Map<String, String> posted = new LinkedHashMap<>();
        Matcher input = HIDDEN_INPUT.matcher(out);
        while (input.find()) {
            posted.put(decode(input.group(1)), decode(input.group(2)));
        }
        Map<String, String> expected = new LinkedHashMap<>(attrs);
        expected.put(SAMLConstants.POST_ATTR_NAMES, "x\"<y:amp:q");
        assertThat(posted).isEqualTo(expected);
    }

    /** Decodes character references as a browser does inside an attribute value. */
    private static String decode(String s) {
        Matcher m = CHAR_REF.matcher(s);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String ref = m.group(1);
            String ch;
            if (ref.startsWith("#x")) {
                ch = new String(Character.toChars(Integer.parseInt(ref.substring(2), 16)));
            } else if (ref.startsWith("#")) {
                ch = new String(Character.toChars(Integer.parseInt(ref.substring(1))));
            } else if ("quot".equals(ref)) {
                ch = "\"";
            } else if ("amp".equals(ref)) {
                ch = "&";
            } else if ("lt".equals(ref)) {
                ch = "<";
            } else if ("gt".equals(ref)) {
                ch = ">";
            } else if ("apos".equals(ref)) {
                ch = "'";
            } else {
                throw new AssertionError("Unexpected entity: &" + ref + ";");
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(ch));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Partner B's certificate is in the keystore too, so a message that claims issuer A
     * and carries B's certificate in KeyInfo must not verify as A's.
     */
    @Test
    public void checkSignatureValidRejectsAnotherPartnersCertificate() throws Exception {
        String signedByPartnerB = signWithPrivateKey();

        assertThat(SAMLUtils.checkSignatureValid(signedByPartnerB, ID_ATTRIBUTE, ISSUER,
                partnerWithCertAlias("defaultkey"))).isFalse();
    }

    @Test
    public void checkSignatureValidAcceptsTheIssuersOwnCertificate() throws Exception {
        String signedByPartnerB = signWithPrivateKey();

        assertThat(SAMLUtils.checkSignatureValid(signedByPartnerB, ID_ATTRIBUTE, ISSUER,
                partnerWithCertAlias("privatekey"))).isTrue();
    }

    @Test
    public void checkSignatureValidRejectsPartnerWithoutCertAlias() throws Exception {
        String signedByPartnerB = signWithPrivateKey();

        assertThat(SAMLUtils.checkSignatureValid(signedByPartnerB, ID_ATTRIBUTE, ISSUER,
                partnerWithCertAlias(null))).isFalse();
    }

    /**
     * Production code enters through the 3-arg overload, which must look the issuer up in
     * PARTNER_URLS; without that lookup there is no expected alias and any keystore
     * certificate is accepted again. Mockito 2 has no mockStatic, so the service
     * manager's static state is seeded by reflection.
     */
    @Test
    public void publicCheckSignatureValidBindsTheIssuerFromPartnerUrls() throws Exception {
        String signedByPartnerB = signWithPrivateKey();
        Field instance = SAMLServiceManager.class.getDeclaredField("instance");
        Field map = SAMLServiceManager.class.getDeclaredField("map");
        Constructor<SAMLServiceManager> constructor = SAMLServiceManager.class.getDeclaredConstructor();
        instance.setAccessible(true);
        map.setAccessible(true);
        constructor.setAccessible(true);
        Object savedInstance = instance.get(null);
        Object savedMap = map.get(null);
        try {
            instance.set(null, constructor.newInstance());
            map.set(null, Collections.singletonMap(SAMLConstants.PARTNER_URLS, partnerWithCertAlias("defaultkey")));

            assertThat(SAMLUtils.checkSignatureValid(signedByPartnerB, ID_ATTRIBUTE, ISSUER)).isFalse();
        } finally {
            instance.set(null, savedInstance);
            map.set(null, savedMap);
        }
    }

    private static Map<String, SAMLServiceManager.SOAPEntry> partnerWithCertAlias(String certAlias) {
        SAMLServiceManager.SOAPEntry partner = mock(SAMLServiceManager.SOAPEntry.class);
        when(partner.getCertAlias()).thenReturn(certAlias);
        return Collections.singletonMap(ISSUER, partner);
    }

    private static String signWithPrivateKey() throws Exception {
        String keyStore = URLEncDec.decode(ClassLoader.getSystemResource("keystore.jks").getFile());
        XMLSignatureManager signer = XMLSignatureManager.getInstance(
                new AMKeyProvider(true, keyStore, "testcase", "JKS", "testcase"), new AMSignatureProvider());
        Document document = XMLUtils.toDOMDocument(
                ClassLoader.getSystemResourceAsStream("documenttosign.xml"), SAML2Utils.debug);
        signer.signXMLUsingKeyPass(document, "privatekey",
                AccessController.doPrivileged(new EncodeAction("keypass")), null, ID_ATTRIBUTE, "signme", true, null);
        return XMLUtils.print(document.getDocumentElement());
    }

    @DataProvider
    public Object[][] hostsInDomain() {
        return new Object[][] {
            {"sp.example.com", "sp.example.com"},
            {"www.sp.example.com", "sp.example.com"},
            {"sp.example.com", "example.com"},
            {"SP.Example.COM", "sp.example.com"},
            {"sp.example.com", " SP.EXAMPLE.COM "},
            {"sp.example.com.", "sp.example.com"},
            {"sp.example.com", ".example.com"},
        };
    }

    @Test(dataProvider = "hostsInDomain")
    public void hostInPartnerDomainMatches(String host, String domain) {
        assertThat(SAMLUtils.isHostInDomain(host, domain)).isTrue();
    }

    @DataProvider
    public Object[][] hostsOutsideDomain() {
        return new Object[][] {
            {"sp.example.com.attacker.com", "sp.example.com"},
            {"evilsp.example.com", "sp.example.com"},
            {"attacker-sp.example.com.evil", "sp.example.com"},
            {"attacker.com", "sp.example.com"},
            {"example.com", "sp.example.com"},
            {"sp.example.com", ""},
            {"sp.example.com", "."},
            {"sp.example.com", null},
            {null, "sp.example.com"},
            {"", ""},
            {"", "."},
            {null, null},
            // java.net.URL before JDK 20 leaves these characters in the host
            {"attacker.com\\.sp.example.com", "sp.example.com"},
            {"attacker.com%5c.sp.example.com", "sp.example.com"},
            // IPv6 literals are not supported as partner targets
            {"[::1]", "[::1]"},
        };
    }

    @Test(dataProvider = "hostsOutsideDomain")
    public void hostThatOnlyContainsPartnerDomainDoesNotMatch(String host, String domain) {
        assertThat(SAMLUtils.isHostInDomain(host, domain)).isFalse();
    }

    @Test
    public void trustedSiteRejectsTargetThatOnlyContainsPartnerHost() {
        Set<SiteEntry> sites = sites(site("sp.example.com", -1));

        assertThat(SAMLUtils.getTrustedSite(sites, "sp.example.com.attacker.com", -1)).isNull();
        assertThat(SAMLUtils.getTrustedSite(sites, "evilsp.example.com", 443)).isNull();
    }

    @Test
    public void trustedSiteWithoutPortAcceptsAnyPort() {
        SiteEntry sp = site("sp.example.com", -1);

        assertThat(SAMLUtils.getTrustedSite(sites(sp), "sp.example.com", -1)).isSameAs(sp);
        assertThat(SAMLUtils.getTrustedSite(sites(sp), "app.sp.example.com", 8443)).isSameAs(sp);
    }

    @Test
    public void trustedSiteWithPortRequiresThatPort() {
        SiteEntry sp = site("sp.example.com", 8443);

        assertThat(SAMLUtils.getTrustedSite(sites(sp), "sp.example.com", 8443)).isSameAs(sp);
        assertThat(SAMLUtils.getTrustedSite(sites(sp), "sp.example.com", 443)).isNull();
        assertThat(SAMLUtils.getTrustedSite(sites(sp), "sp.example.com", -1)).isNull();
    }

    @Test
    public void mostSpecificTrustedSiteWins() {
        SiteEntry domain = site("example.com", -1);
        SiteEntry host = site("sp.example.com", -1);
        SiteEntry hostAndPort = site("sp.example.com", 8443);
        Set<SiteEntry> sites = sites(domain, host, hostAndPort);

        assertThat(SAMLUtils.getTrustedSite(sites, "other.example.com", 443)).isSameAs(domain);
        assertThat(SAMLUtils.getTrustedSite(sites, "sp.example.com", 443)).isSameAs(host);
        assertThat(SAMLUtils.getTrustedSite(sites, "sp.example.com", 8443)).isSameAs(hostAndPort);

        Set<SiteEntry> reversed = sites(hostAndPort, host, domain);

        assertThat(SAMLUtils.getTrustedSite(reversed, "other.example.com", 443)).isSameAs(domain);
        assertThat(SAMLUtils.getTrustedSite(reversed, "sp.example.com", 443)).isSameAs(host);
        assertThat(SAMLUtils.getTrustedSite(reversed, "sp.example.com", 8443)).isSameAs(hostAndPort);
    }

    @Test
    public void specificityIgnoresLeadingAndTrailingDots() {
        SiteEntry dottedDomain = site(".sp.example.com", -1);
        SiteEntry hostAndPort = site("sp.example.com", 8443);
        SiteEntry dottedParent = site(".example.com.", 443);
        SiteEntry subdomain = site("a.example.com", -1);

        assertThat(SAMLUtils.getTrustedSite(sites(dottedDomain, hostAndPort), "sp.example.com", 8443))
                .isSameAs(hostAndPort);
        assertThat(SAMLUtils.getTrustedSite(sites(dottedParent, subdomain), "a.example.com", 443))
                .isSameAs(subdomain);
    }

    @Test
    public void trustedSiteForTargetUrl() throws Exception {
        SiteEntry sp = site("sp.example.com", -1);

        assertThat(SAMLUtils.getTrustedSite(sites(sp), "https://sp.example.com.attacker.com/x")).isNull();
        assertThat(SAMLUtils.getTrustedSite(sites(sp), "https://evilsp.example.com/x")).isNull();
        assertThat(SAMLUtils.getTrustedSite(sites(sp), "https://app.sp.example.com:8443/x")).isSameAs(sp);
        assertThat(SAMLUtils.getTrustedSite(sites(sp), "https://sp.example.com/x?next=a\\b")).isSameAs(sp);
    }

    @Test
    public void targetUrlWithUserInfoIsRejected() throws Exception {
        SiteEntry sp = site("sp.example.com", -1);

        assertThat(SAMLUtils.getTrustedSite(sites(sp), "http://user@sp.example.com/")).isNull();
    }

    /**
     * Browsers read a backslash in an http(s) authority as a slash, so these
     * TARGETs lead to attacker.com. java.net.URL rejects them from JDK 20 on;
     * before that it parses them, and the host must not match.
     */
    @Test
    public void targetUrlWithBackslashInAuthorityIsRejected() {
        SiteEntry sp = site("sp.example.com", -1);

        assertNoTrustedSite(sites(sp), "http://attacker.com\\@sp.example.com/x");
        assertNoTrustedSite(sites(sp), "http://attacker.com\\.sp.example.com/x");
    }

    private static void assertNoTrustedSite(Set<SiteEntry> sites, String target) {
        try {
            assertThat(SAMLUtils.getTrustedSite(sites, target)).isNull();
        } catch (MalformedURLException expected) {
            // JDK 20+
        }
    }

    @Test
    public void noTrustedSitesMeansNoMatch() {
        assertThat(SAMLUtils.getTrustedSite(null, "sp.example.com", -1)).isNull();
        assertThat(SAMLUtils.getTrustedSite(sites(), "sp.example.com", -1)).isNull();
    }

    private static SiteEntry site(String host, int port) {
        return new SiteEntry(host, port, "sourceID", "https://" + host + "/saml", null, "1.1");
    }

    private static Set<SiteEntry> sites(SiteEntry... entries) {
        return new LinkedHashSet<>(Arrays.asList(entries));
    }
}
