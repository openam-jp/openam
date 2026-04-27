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

import java.util.ArrayList;
import java.util.List;

import org.forgerock.guava.common.annotations.VisibleForTesting;

import com.sun.identity.authentication.service.AuthD;
import com.sun.identity.saml2.jaxb.metadata.AttributeConsumingServiceElement;
import com.sun.identity.saml2.jaxb.metadata.EntityDescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.ExtensionsType;
import com.sun.identity.saml2.jaxb.metadata.OrganizationDisplayNameElement;
import com.sun.identity.saml2.jaxb.metadata.OrganizationType;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.ServiceDescriptionElement;
import com.sun.identity.saml2.jaxb.metadata.ServiceNameElement;
import com.sun.identity.saml2.jaxb.metadataui.DescriptionElement;
import com.sun.identity.saml2.jaxb.metadataui.DisplayNameElement;
import com.sun.identity.saml2.jaxb.metadataui.InformationURLElement;
import com.sun.identity.saml2.jaxb.metadataui.LogoElement;
import com.sun.identity.saml2.jaxb.metadataui.PrivacyStatementURLElement;
import com.sun.identity.saml2.jaxb.metadataui.UIInfoElement;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.profile.IDPSSOUtil;

/**
 * The class <code>UIInfoCollector</code> collects informations to be shown to
 * users about SAML2 service providers.
 */
public class UIInfoCollector {

    private String realm;
    private String spEntityId;

    public UIInfoCollector(String realm, String spEntityId) {
        this.realm = realm;
        this.spEntityId = spEntityId;
    }

    public boolean spExists() throws SAML2MetaException {
        return getSPSSODescriptor() != null;
    }

    public LogoInfo getLogoInfo(String lang) throws SAML2MetaException {
        UIInfoElement uiInfoElement = getUIInfoElement();
        if (uiInfoElement == null) {
            return null;
        }
        List uiinfos = uiInfoElement.getDisplayNameOrDescriptionOrKeywords();
        List<LogoElement> logos = extractInstanceOf(LogoElement.class, uiinfos);
        if (logos.isEmpty()) {
            return null;
        }

        // Prioritize logos with language
        for (LogoElement logo : logos) {
            if (lang.equals(logo.getLang())) {
                return createLogoInfo(logo);
            }
        }
        for (LogoElement logo : logos) {
            if (getPlatformLanguage().equals(logo.getLang())) {
                return createLogoInfo(logo);
            }
        }

        // If there is a logo with no language, it will be used.
        for (LogoElement logo : logos) {
            if (logo.getLang() == null) {
                return createLogoInfo(logo);
            }
        }

        return null;
    }

    public String getDisplayName(String lang) throws SAML2MetaException {
        UIInfoElement uiInfoElement = getUIInfoElement();
        if (uiInfoElement != null) {
            List uiInfo = uiInfoElement.getDisplayNameOrDescriptionOrKeywords();
            List<DisplayNameElement> displayNames = extractInstanceOf(DisplayNameElement.class, uiInfo);
            for (DisplayNameElement displayName : displayNames) {
                if (lang.equals(displayName.getLang())) {
                    return displayName.getValue();
                }
            }
            for (DisplayNameElement displayName : displayNames) {
                if (getPlatformLanguage().equals(displayName.getLang())) {
                    return displayName.getValue();
                }
            }
        }

        AttributeConsumingServiceElement attributeConsumingServiceElement = getAttributeConsumingServiceElement();
        if (attributeConsumingServiceElement != null) {
            List<ServiceNameElement> serviceNameElements = attributeConsumingServiceElement.getServiceName();
            for (ServiceNameElement serviceName : serviceNameElements) {
                if (lang.equals(serviceName.getLang())) {
                    return serviceName.getValue();
                }
            }
            for (ServiceNameElement serviceName : serviceNameElements) {
                if (getPlatformLanguage().equals(serviceName.getLang())) {
                    return serviceName.getValue();
                }
            }
        }
        return spEntityId;
    }

    public String getDescription(String lang) throws SAML2MetaException {
        UIInfoElement uiInfoElement = getUIInfoElement();
        if (uiInfoElement != null) {
            List uiinfo = uiInfoElement.getDisplayNameOrDescriptionOrKeywords();
            List<DescriptionElement> descriptionElements = extractInstanceOf(DescriptionElement.class, uiinfo);
            for (DescriptionElement description : descriptionElements) {
                if (lang.equals(description.getLang())) {
                    return description.getValue();
                }
            }
            for (DescriptionElement description : descriptionElements) {
                if (getPlatformLanguage().equals(description.getLang())) {
                    return description.getValue();
                }
            }
        }

        AttributeConsumingServiceElement attributeConsumingServiceElement = getAttributeConsumingServiceElement();
        if (attributeConsumingServiceElement != null) {
            List<ServiceDescriptionElement> serviceDescriptionElements = attributeConsumingServiceElement
                    .getServiceDescription();
            for (ServiceDescriptionElement serviceDescription : serviceDescriptionElements) {
                if (lang.equals(serviceDescription.getLang())) {
                    return serviceDescription.getValue();
                }
            }
            for (ServiceDescriptionElement serviceDescription : serviceDescriptionElements) {
                if (getPlatformLanguage().equals(serviceDescription.getLang())) {
                    return serviceDescription.getValue();
                }
            }
        }
        return null;
    }

    public String getInformationURL(String lang) throws SAML2MetaException {
        UIInfoElement uiInfoElement = getUIInfoElement();
        if (uiInfoElement == null) {
            return null;
        }

        List<Object> uiinfo = uiInfoElement.getDisplayNameOrDescriptionOrKeywords();
        List<InformationURLElement> informationURLElements = extractInstanceOf(InformationURLElement.class, uiinfo);
        for (InformationURLElement informationURL : informationURLElements) {
            if (lang.equals(informationURL.getLang())) {
                return informationURL.getValue();
            }
        }
        for (InformationURLElement informationURL : informationURLElements) {
            if (getPlatformLanguage().equals(informationURL.getLang())) {
                return informationURL.getValue();
            }
        }
        return null;
    }

    public String getPrivacyStatementURL(String lang) throws SAML2MetaException {
        UIInfoElement uiInfoElement = getUIInfoElement();
        if (uiInfoElement == null) {
            return null;
        }

        List<Object> uiinfo = uiInfoElement.getDisplayNameOrDescriptionOrKeywords();
        List<PrivacyStatementURLElement> privacyStatementURLElements = extractInstanceOf(
                PrivacyStatementURLElement.class, uiinfo);
        for (PrivacyStatementURLElement privacyStatementURL : privacyStatementURLElements) {
            if (lang.equals(privacyStatementURL.getLang())) {
                return privacyStatementURL.getValue();
            }
        }
        for (PrivacyStatementURLElement privacyStatementURL : privacyStatementURLElements) {
            if (getPlatformLanguage().equals(privacyStatementURL.getLang())) {
                return privacyStatementURL.getValue();
            }
        }
        return null;
    }

    public String getOrganizationDisplayName(String lang) throws SAML2MetaException {
        OrganizationType organizationType = getOrganizationElement();
        if (organizationType == null) {
            return null;
        }
        List<OrganizationDisplayNameElement> organizationDisplayNameElements = organizationType
                .getOrganizationDisplayName();
        for (OrganizationDisplayNameElement organisationDispalyName : organizationDisplayNameElements) {
            if (lang.equals(organisationDispalyName.getLang())) {
                return organisationDispalyName.getValue();
            }
        }
        for (OrganizationDisplayNameElement organisationDispalyName : organizationDisplayNameElements) {
            if (getPlatformLanguage().equals(organisationDispalyName.getLang())) {
                return organisationDispalyName.getValue();
            }
        }
        return null;
    }

    private EntityDescriptorElement getEntityDescriptor() throws SAML2MetaException {
        return getMetaManager().getEntityDescriptor(realm, spEntityId);

    }

    private SPSSODescriptorElement getSPSSODescriptor() throws SAML2MetaException {
        return getMetaManager().getSPSSODescriptor(realm, spEntityId);

    }

    private UIInfoElement getUIInfoElement() throws SAML2MetaException {
        SPSSODescriptorElement spssoDescriptor = getSPSSODescriptor();
        if (spssoDescriptor == null) {
            return null;
        }
        ExtensionsType extensionsType = spssoDescriptor.getExtensions();
        if (extensionsType == null) {
            return null;
        }
        List extensions = extensionsType.getAny();
        for (Object extension : extensions) {
            if (extension instanceof UIInfoElement) {
                return (UIInfoElement) extension;
            }
        }
        return null;
    }

    private AttributeConsumingServiceElement getAttributeConsumingServiceElement() throws SAML2MetaException {
        SPSSODescriptorElement spssoDescriptorElement = getSPSSODescriptor();
        if (spssoDescriptorElement == null) {
            return null;
        }
        List<AttributeConsumingServiceElement> elements = spssoDescriptorElement.getAttributeConsumingService();
        if (!elements.isEmpty()) {
            return elements.get(0);
        }
        return null;
    }

    private OrganizationType getOrganizationElement() throws SAML2MetaException {
        SPSSODescriptorElement spssoDescriptor = getSPSSODescriptor();
        if (spssoDescriptor != null) {
            OrganizationType organizationElement = spssoDescriptor.getOrganization();
            if (organizationElement != null) {
                return organizationElement;
            }
        }
        EntityDescriptorElement entityDescriptor = getEntityDescriptor();
        if (entityDescriptor != null) {
            OrganizationType organizationElement = entityDescriptor.getOrganization();
            if (organizationElement != null) {
                return organizationElement;
            }
        }
        return null;
    }

    private LogoInfo createLogoInfo(LogoElement element) {
        String url = element.getValue();
        int height = element.getHeight().intValue();
        int width = element.getWidth().intValue();
        LogoInfo logoInfo = new LogoInfo(url, height, width);
        return logoInfo;
    }

    private List extractInstanceOf(Class clazz, List input) {
        List answer = new ArrayList<>();
        for (Object obj : input) {
            if (clazz.isInstance(obj)) {
                answer.add(obj);
            }
        }
        return answer;
    }

    @VisibleForTesting
    SAML2MetaManager getMetaManager() {
        return IDPSSOUtil.metaManager;
    }

    @VisibleForTesting
    String getPlatformLanguage() {
        String platformLocale = AuthD.getAuth().getPlatformLocale();
        return platformLocale.split("_")[0];
    }
}
