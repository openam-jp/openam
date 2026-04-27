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
package jp.co.osstech.openam.saml2.metadata;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.sun.identity.saml2.jaxb.metadata.EntityDescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorElement;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.meta.SAML2MetaUtils;

public class UIInfoCollectorTest {

    private static final String REALM = "/testrealm";
    private static final String SP_ENTITY_ID = "https://sp.example.com";
    private static final String SP_METADATA_TEMPLATE_FILE = "sp-metadata-template-UIInfoCollectorTest.xml";

    @Mock
    SAML2MetaManager manager;

    UIInfoCollector collector;

    List<String> uiinfo;
    List<String> serviceNames;
    List<String> serviceDescriptions;
    List<String> organizationInSPSSODescriptor;
    List<String> organizationInEntityDescriptor;

    @BeforeMethod
    public void setup() throws Exception {
        uiinfo = new ArrayList<>();
        serviceNames = new ArrayList<>();
        serviceDescriptions = new ArrayList<>();
        organizationInSPSSODescriptor = new ArrayList<>();
        organizationInEntityDescriptor = new ArrayList<>();

        MockitoAnnotations.initMocks(this);

        collector = new UIInfoCollector(REALM, SP_ENTITY_ID);

        collector = spy(collector);
        when(collector.getMetaManager()).thenReturn(manager);
        setPlatformLang("en");
        when(manager.getEntityDescriptor(REALM, SP_ENTITY_ID)).thenAnswer(new EntityDescriptorAnswer());
        when(manager.getSPSSODescriptor(REALM, SP_ENTITY_ID)).thenAnswer(new SPSSODescriptorAnswer());
    }

    @Test
    public void returnLocalizedLogo() throws Exception {

        addLogoElement(200, 60, null, "https://example.com/logo/default.png");
        addLogoElement(200, 60, "en", "https://example.com/logo/english.png");
        addLogoElement(100, 30, "ja", "https://example.com/logo/japanese.png");

        LogoInfo logoInfo = collector.getLogoInfo("ja");

        assertNotNull(logoInfo);
        assertEquals(100, logoInfo.getWidth());
        assertEquals(30, logoInfo.getHeight());
        assertEquals("https://example.com/logo/japanese.png", logoInfo.getUrl());
    }

    @Test
    public void returnPlatformLanguageLogoIfLanguageNotMatched() throws Exception {

        addLogoElement(200, 60, null, "https://example.com/logo/default.png");
        addLogoElement(200, 60, "en", "https://example.com/logo/english.png");
        setPlatformLang("en");

        LogoInfo logoInfo = collector.getLogoInfo("ja");

        assertNotNull(logoInfo);
        assertEquals(200, logoInfo.getWidth());
        assertEquals(60, logoInfo.getHeight());
        assertEquals("https://example.com/logo/english.png", logoInfo.getUrl());
    }

    @Test
    public void returnDefaultLogoIfLanguageNotMatched() throws Exception {

        addLogoElement(200, 60, null, "https://example.com/logo/default.png");
        setPlatformLang("en");

        LogoInfo logoInfo = collector.getLogoInfo("ja");

        assertNotNull(logoInfo);
        assertEquals(200, logoInfo.getWidth());
        assertEquals(60, logoInfo.getHeight());
        assertEquals("https://example.com/logo/default.png", logoInfo.getUrl());
    }

    @Test
    public void returnNullLogoIfLanguageNotMatchedAndNoDefaultLogo() throws Exception {
        addLogoElement(100, 30, "ja", "https://example.com/logo/japanese.png");
        setPlatformLang("en");

        LogoInfo logoInfo = collector.getLogoInfo("fr");

        assertNull(logoInfo);
    }

    @Test
    public void returnNullIfMetadataHasNoLogoInfoElement() throws Exception {
        LogoInfo logoInfo = collector.getLogoInfo("en");

        assertNull(logoInfo);
    }

    @Test
    public void returnLocalizedDisplayNameInUIInfo() throws Exception {

        addDisplayName("ja", "ja_displayName");
        addDisplayName("en", "en_displayName");

        assertEquals("ja_displayName", collector.getDisplayName("ja"));
    }

    @Test
    public void returnPlatformLanguageDisplayNameIfLanguageNotMatched() throws Exception {

        addDisplayName("en", "en_displayName");
        setPlatformLang("en");

        assertEquals("en_displayName", collector.getDisplayName("ja"));
    }

    @Test
    public void returnServiceNameIfUIInfoIsNull() throws Exception {

        addServiceName("ja", "ja_serviceName");
        addServiceName("en", "en_serviceName");

        assertEquals("ja_serviceName", collector.getDisplayName("ja"));
    }

    @Test
    public void returnPlatformLanguageServiceNameIfLanguageNotMatched() throws Exception {

        addServiceName("en", "en_serviceName");
        setPlatformLang("en");

        assertEquals("en_serviceName", collector.getDisplayName("ja"));
    }

    @Test
    public void displayNameTakesPrecedenceOverServiceName() throws Exception {
        addDisplayName("ja", "ja_displayName");
        addServiceName("ja", "ja_serviceName");

        assertEquals("ja_displayName", collector.getDisplayName("ja"));
    }

    @Test
    public void returnEntityIdIfNoDisplayNameInfoIsPresent() throws Exception {
        assertEquals(SP_ENTITY_ID, collector.getDisplayName("ja"));
    }

    @Test
    public void returnEntityIdIfPlatformLanguageNotMatched() throws Exception {
        addServiceName("ja", "ja_serviceName");
        setPlatformLang("en");

        assertEquals(SP_ENTITY_ID, collector.getDisplayName("fr"));
    }

    @Test
    public void returnLocalizedDescriptionInUIInfo() throws Exception {
        addUIInfoDescription("ja", "ja_description");
        addUIInfoDescription("en", "en_description");

        assertEquals("ja_description", collector.getDescription("ja"));
    }

    @Test
    public void returnPlatformLanguageDescriptionIfLanguageNotMatched() throws Exception {
        addUIInfoDescription("en", "en_description");
        setPlatformLang("en");

        assertEquals("en_description", collector.getDescription("ja"));
    }

    @Test
    public void returnLocalizedDescriptionInAttributeConsumingService() throws Exception {
        addServiceDescription("ja", "ja_description");
        addServiceDescription("en", "en_description");

        assertEquals("ja_description", collector.getDescription("ja"));
    }

    @Test
    public void returnPlatformLanguageDescriptionInAttributeConsumingServiceIfLanguageNotMatched() throws Exception {
        addServiceDescription("en", "en_description");
        setPlatformLang("en");

        assertEquals("en_description", collector.getDescription("ja"));
    }

    @Test
    public void descriptionInUIInfoTakesPrecedenceOverDescriptionInAttributeConsumingService() throws Exception {
        addUIInfoDescription("ja", "ja_uiinfo_description");
        addServiceDescription("ja", "ja_service_description");

        assertEquals("ja_uiinfo_description", collector.getDescription("ja"));
    }

    @Test
    public void returnNullIfDescriptionNotFound() throws Exception {
        assertNull(collector.getDescription("ja"));
    }

    @Test
    public void returnNullDescriptionIfPlatformLanguageNotMatcehd() throws Exception {
        addUIInfoDescription("ja", "ja_uiinfo_description");
        setPlatformLang("en");

        assertNull(collector.getDescription("fr"));
    }

    @Test
    public void returnLocalizedInformationURL() throws Exception {
        addInformationURL("ja", "https://example.com/ja");
        addInformationURL("en", "https://example.com/en");

        assertEquals("https://example.com/ja", collector.getInformationURL("ja"));
    }

    @Test
    public void returnPlatformLanguageInformationURLIfLanguageNotMatched() throws Exception {
        addInformationURL("en", "https://example.com/en");
        setPlatformLang("en");

        assertEquals("https://example.com/en", collector.getInformationURL("ja"));
    }

    @Test
    public void retunNullIfInformationURLNotFound() throws Exception {
        assertNull(collector.getInformationURL("ja"));
    }

    @Test
    public void returnNullInformationURLIfPlatformLanguageNotMatched() throws Exception {
        addInformationURL("ja", "https://example.com/ja");
        setPlatformLang("en");

        assertNull(collector.getInformationURL("fr"));
    }

    @Test
    public void returnLocalizedPrivacyStatementURL() throws Exception {
        addPrivacyStatementURL("ja", "https://example.com/ja");
        addPrivacyStatementURL("en", "https://example.com/en");

        assertEquals("https://example.com/ja", collector.getPrivacyStatementURL("ja"));
    }

    @Test
    public void returnPlatformLanguagePrivacyStatementURLIfLanguageNotMatched() throws Exception {
        addPrivacyStatementURL("en", "https://example.com/en");
        setPlatformLang("en");

        assertEquals("https://example.com/en", collector.getPrivacyStatementURL("ja"));
    }

    @Test
    public void returnNullIfPrivacyStatementURLNotFound() throws Exception {
        assertNull(collector.getPrivacyStatementURL("ja"));
    }

    @Test
    public void returnNullPrivacyStatementURLIfPlatformLanguageNotMatched() throws Exception {
        addPrivacyStatementURL("ja", "https://example.com/ja");
        setPlatformLang("en");

        assertNull(collector.getPrivacyStatementURL("fr"));
    }

    @Test
    public void returnLocalizedOrganizationDisplayNameInSPSSODescriptor() throws Exception {
        addOrganizationDisplayNameInSPSSODescriptor("ja", "ja_displayName");
        addOrganizationDisplayNameInSPSSODescriptor("en", "en_displayName");

        assertEquals("ja_displayName", collector.getOrganizationDisplayName("ja"));
    }

    @Test
    public void returnPlatformLanguageOrganizationDisplayNameIfLanguageNotMatched() throws Exception {
        addOrganizationDisplayNameInSPSSODescriptor("en", "en_displayName");
        setPlatformLang("en");

        assertEquals("en_displayName", collector.getOrganizationDisplayName("ja"));
    }

    @Test
    public void returnNullIfOrganizationDisplayNameNotFound() throws Exception {
        assertNull(collector.getOrganizationDisplayName("ja"));
    }

    @Test
    public void returnNullOrganizationDisplayNameIfPlatformLanguageNotMatched() throws Exception {
        addOrganizationDisplayNameInSPSSODescriptor("ja", "ja_displayName");
        setPlatformLang("en");

        assertNull(collector.getOrganizationDisplayName("fr"));
    }

    @Test
    public void returnLocalizedOrganizationDisplayNameInEntityDescriptor() throws Exception {
        addOrganizationDisplayNameInEntityDescriptor("ja", "ja_displayname");
        addOrganizationDisplayNameInEntityDescriptor("en", "en_displayname");

        assertEquals("ja_displayname", collector.getOrganizationDisplayName("ja"));
    }

    @Test
    public void returnPlatformLanguageOrganizationDisplayNameInEntityDescriptorIfLanguageNotMatched()
            throws Exception {
        addOrganizationDisplayNameInEntityDescriptor("en", "en_displayname");
        setPlatformLang("en");

        assertEquals("en_displayname", collector.getOrganizationDisplayName("ja"));
    }

    @Test
    public void seeSPSSODescriptorBeforeEntityDescriptor() throws Exception {
        addOrganizationDisplayNameInSPSSODescriptor("ja", "displayname_in_spssodescriptor");
        addOrganizationDisplayNameInEntityDescriptor("ja", "displayname_in_entitydescriptor");

        assertEquals("displayname_in_spssodescriptor", collector.getOrganizationDisplayName("ja"));
    }

    private void addLogoElement(int width, int height, String lang, String url) {
        String template;
        if (lang == null) {
            template = "<mdui:Logo height=\"%d\" width=\"%d\">%s</mdui:Logo>";
            uiinfo.add(String.format(template, height, width, url));
        } else {
            template = "<mdui:Logo height=\"%d\" width=\"%d\" xml:lang=\"%s\">%s</mdui:Logo>";
            uiinfo.add(String.format(template, height, width, lang, url));
        }
    }

    private void addDisplayName(String lang, String displayName) {
        String template = "<mdui:DisplayName xml:lang=\"%s\">%s</mdui:DisplayName>";
        uiinfo.add(String.format(template, lang, displayName));
    }

    private void addServiceName(String lang, String ServiceName) {
        String template = "<ServiceName xml:lang=\"%s\">%s</ServiceName>";
        serviceNames.add(String.format(template, lang, ServiceName));
    }

    private void addUIInfoDescription(String lang, String description) {
        String template = "<mdui:Description xml:lang=\"%s\">%s</mdui:Description>";
        uiinfo.add(String.format(template, lang, description));
    }

    private void addServiceDescription(String lang, String description) {
        String template = "<ServiceDescription xml:lang=\"%s\">%s</ServiceDescription>";
        serviceDescriptions.add(String.format(template, lang, description));
    }

    private void addInformationURL(String lang, String url) {
        String template = "<mdui:InformationURL xml:lang=\"%s\">%s</mdui:InformationURL>";
        uiinfo.add(String.format(template, lang, url));
    }

    private void addPrivacyStatementURL(String lang, String url) {
        String template = "<mdui:PrivacyStatementURL xml:lang=\"%s\">%s</mdui:PrivacyStatementURL>";
        uiinfo.add(String.format(template, lang, url));
    }

    private void addOrganizationDisplayNameInSPSSODescriptor(String lang, String displayName) {
        String template = "<OrganizationDisplayName xml:lang=\"%s\">%s</OrganizationDisplayName>";
        organizationInSPSSODescriptor.add(String.format(template, lang, displayName));
    }

    private void addOrganizationDisplayNameInEntityDescriptor(String lang, String displayName) {
        String template = "<OrganizationDisplayName xml:lang=\"%s\">%s</OrganizationDisplayName>";
        organizationInEntityDescriptor.add(String.format(template, lang, displayName));
    }

    private class EntityDescriptorAnswer implements Answer<EntityDescriptorElement> {
        @Override
        public EntityDescriptorElement answer(InvocationOnMock invocation) throws Throwable {
            String metadata = renderTemplate();
            return (EntityDescriptorElement) SAML2MetaUtils.convertStringToJAXB(metadata);
        }
    }

    private class SPSSODescriptorAnswer implements Answer<SPSSODescriptorElement> {
        @Override
        public SPSSODescriptorElement answer(InvocationOnMock invocation) throws Throwable {
            String metadata = renderTemplate();
            EntityDescriptorElement entityDescriptor = (EntityDescriptorElement) SAML2MetaUtils
                    .convertStringToJAXB(metadata);
            SPSSODescriptorElement spssoDescriptor = (SPSSODescriptorElement) entityDescriptor
                    .getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().get(0);
            return spssoDescriptor;
        }
    }

    private String renderTemplate() throws IOException {
        String template = IOUtils.toString(ClassLoader.getSystemResourceAsStream(SP_METADATA_TEMPLATE_FILE));
        template = template.replace("@ORGANIZATION1@", getOrganizationInSPSSODescriptor());
        template = template.replace("@EXTENSIONS@", getExtensions());
        template = template.replace("@ATTRIBUTE_CONSUMING_SERVICE@", getAttributeConsumingService());
        template = template.replace("@ORGANIZATION2@", getOrganizationInEntityDescriptor());
        return template;
    }

    private String getExtensions() {
        if (uiinfo.isEmpty()) {
            return "";
        }
        String extensionElement = new StringBuilder()
                .append("<Extensions>")
                .append("<mdui:UIInfo xmlns:mdui=\"urn:oasis:names:tc:SAML:metadata:ui\">")
                .append(String.join("", uiinfo))
                .append("</mdui:UIInfo>")
                .append("</Extensions>")
                .toString();
        return extensionElement;
    }

    private String getAttributeConsumingService() {
        if (serviceNames.isEmpty() && serviceDescriptions.isEmpty()) {
            return "";
        }
        if (serviceNames.isEmpty()) {
            addServiceName("dummy", "dummy"); // at least one ServiceName element is required.
        }
        String attributeConsumingService = new StringBuilder()
                .append("<AttributeConsumingService index=\"1\">")
                .append(String.join("", serviceNames))
                .append(String.join("", serviceDescriptions))
                .append("<RequestedAttribute Name=\"dummy\"/>") // at least one RequestedAttribute element is required.
                .append("</AttributeConsumingService>")
                .toString();
        return attributeConsumingService;
    }

    private String getOrganizationInSPSSODescriptor() {
        if (organizationInSPSSODescriptor.isEmpty()) {
            return "";
        }
        String organizationElement = new StringBuilder()
                .append("<Organization>")
                // at least one OrganizationName element is required.
                .append("<OrganizationName xml:lang=\"dummy\">dummy</OrganizationName>")
                .append(String.join("", organizationInSPSSODescriptor))
                // at least one OrganizationURL element is required.
                .append("<OrganizationURL xml:lang=\"dummy\">dummy</OrganizationURL>")
                .append("</Organization>")
                .toString();
        return organizationElement;
    }

    private String getOrganizationInEntityDescriptor() {
        if (organizationInEntityDescriptor.isEmpty()) {
            return "";
        }
        String organizationElement = new StringBuilder()
                .append("<Organization>")
                // at least one OrganizationName element is required.
                .append("<OrganizationName xml:lang=\"dummy\">dummy</OrganizationName>")
                .append(String.join("", organizationInEntityDescriptor))
                // at least one OrganizationURL element is required.
                .append("<OrganizationURL xml:lang=\"dummy\">dummy</OrganizationURL>")
                .append("</Organization>")
                .toString();
        return organizationElement;
    }

    private void setPlatformLang(String lang) {
        doReturn(lang).when(collector).getPlatformLanguage();
    }
}
