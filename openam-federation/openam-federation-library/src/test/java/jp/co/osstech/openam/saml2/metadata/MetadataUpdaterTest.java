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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.fail;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.sun.identity.saml2.jaxb.metadata.EntityDescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.IDPSSODescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorElement;
import com.sun.identity.saml2.meta.SAML2MetaManager;

import jp.co.osstech.openam.saml2.metadata.MetadataReloadConfig.TargetRole;

public class MetadataUpdaterTest {

    private static final String REALM = "/sso";

    private static final String SP1 = "https://sp1.example.com";
    private static final String SP2 = "https://sp2.example.com";

    private static final String IDP1 = "https://idp1.example.com";

    @Mock
    SAML2MetaManager manager;

    @Mock
    MetadataReloadConfig config;

    List<String> spInMetadata;
    List<String> idpInMetadata;

    Set<String> includeEntities;
    Set<String> excludeEntities;

    MetadataUpdater updater;

    Calendar metadataExptiration;
    private static final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

    @BeforeMethod
    public void setup() throws Exception {
        MockitoAnnotations.initMocks(this);
        spInMetadata = new ArrayList<>();
        idpInMetadata = new ArrayList<>();
        includeEntities = new HashSet<>();
        excludeEntities = new HashSet<>();
        metadataExptiration = Calendar.getInstance();
        metadataExptiration.set(2022, 05, 26, 15, 0, 0);

        updater = new MetadataUpdater(config, manager);

        when(config.realm()).thenReturn(REALM);
        when(config.targetRole()).thenReturn(TargetRole.ALL);
        when(config.allowCreateEntities()).thenReturn(true);
        when(config.shouldCheckExpirationDate()).thenReturn(false);
        when(config.shouldValidateSignature()).thenReturn(false);
        when(config.includeEntities()).thenReturn(includeEntities);
        when(config.excludeEntities()).thenReturn(excludeEntities);
    }

    @Test
    public void updateEntityIfAlreadyExists() throws Exception {
        registerSP(SP1);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(2)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void createEntityIfNotExistsAndCreatingIsAllowed() throws Exception {
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(1)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
        verify(manager, times(1)).createEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void doNotCreateEntityIfNotExistsButCreatingIsNotAllowed() throws Exception {
        when(config.allowCreateEntities()).thenReturn(false);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(1)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
        verify(manager, never()).createEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void deleteEntity() throws Exception {
        registerSP(SP1);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String backupMetadata = generateMetadate();

        spInMetadata.remove(SP1);
        String newMetadata = generateMetadate();

        updater.update(newMetadata, Optional.of(backupMetadata));
        verify(manager, times(1)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
        verify(manager, times(1)).deleteEntityDescriptor(eq(REALM), eq(SP1));
    }

    @Test
    public void updateSPOnly() throws Exception {
        when(config.targetRole()).thenReturn(TargetRole.SP_ONLY);

        registerSP(SP1);
        registerSP(SP2);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        spInMetadata.add(SP2);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(2)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void updateIDPOnly() throws Exception {
        when(config.targetRole()).thenReturn(TargetRole.IDP_ONLY);

        registerSP(SP1);
        registerSP(SP2);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        spInMetadata.add(SP2);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(1)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void updateNothing() throws Exception {
        when(config.targetRole()).thenReturn(TargetRole.NOTHING);

        registerSP(SP1);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, never()).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void throwsExceptionIfCheckExpirationAndExpired() throws Exception {
        when(config.shouldCheckExpirationDate()).thenReturn(true);

        Calendar validUntil = Calendar.getInstance();
        validUntil.set(2022, 5, 20, 15, 0, 0);
        setMetadataExpiration(validUntil);

        Calendar now = Calendar.getInstance();
        now.set(2022, 5, 26, 10, 0, 0);
        updater = spy(updater);
        doReturn(now).when(updater).getCurrent();

        registerSP(SP1);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        try {
            updater.update(metadata, Optional.<String>empty());
            fail();
        } catch (MetadataReloadFailureException e) {}
    }

    @Test
    public void updateIfCheckExpirationAndValid() throws Exception {
        when(config.shouldCheckExpirationDate()).thenReturn(true);

        Calendar validUntil = Calendar.getInstance();
        validUntil.set(2022, 5, 20, 15, 0, 0);
        setMetadataExpiration(validUntil);

        Calendar now = Calendar.getInstance();
        now.set(2022, 3, 20, 10, 0, 0);
        updater = spy(updater);
        doReturn(now).when(updater).getCurrent();

        registerSP(SP1);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(2)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void throwsExceptionIfValidateSigantureAndFail() throws Exception {
        when(config.shouldValidateSignature()).thenReturn(true);
        updater = spy(updater);
        doReturn(false).when(updater).signatureValid(anyString());

        registerSP(SP1);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        try {
            updater.update(metadata, Optional.<String>empty());
            fail();
        } catch (MetadataReloadFailureException e){}
    }

    @Test
    public void updateIfValidateSigantureAndSuccess() throws Exception {
        when(config.shouldValidateSignature()).thenReturn(true);
        updater = spy(updater);
        doReturn(true).when(updater).signatureValid(anyString());

        registerSP(SP1);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(2)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void includeEntitiesAreAlwaysUpdated() throws Exception {
        when(config.targetRole()).thenReturn(TargetRole.SP_ONLY);
        includeEntities.add(IDP1);

        registerSP(SP1);
        registerSP(SP2);
        registerIdP(IDP1);

        spInMetadata.add(SP1);
        spInMetadata.add(SP2);
        idpInMetadata.add(IDP1);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(3)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    @Test
    public void exludeEntitiesAreAlwaysNotUpdated() throws Exception {
        when(config.targetRole()).thenReturn(TargetRole.SP_ONLY);
        excludeEntities.add(SP2);

        registerSP(SP1);
        registerSP(SP2);

        spInMetadata.add(SP1);
        spInMetadata.add(SP2);
        String metadata = generateMetadate();

        updater.update(metadata, Optional.<String>empty());
        verify(manager, times(1)).setEntityDescriptor(eq(REALM), any(EntityDescriptorElement.class));
    }

    private enum EntityRole {
        SP,
        IDP
    }

    private void registerSP(String spEntityId) throws Exception {
        registerEntity(spEntityId, EntityRole.SP);
    }

    private void registerIdP(String idpEntotyId) throws Exception {
        registerEntity(idpEntotyId, EntityRole.IDP);
    }

    private void registerEntity(String entityId, EntityRole role) throws Exception {
        EntityDescriptorElement entityDescriptor = mock(EntityDescriptorElement.class);

        if (role == EntityRole.SP) {
            SPSSODescriptorElement spssoDescriptor = mock(SPSSODescriptorElement.class);
            when(entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor())
                    .thenReturn(Arrays.asList(spssoDescriptor));
        } else {
            IDPSSODescriptorElement idpssoDescriptor = mock(IDPSSODescriptorElement.class);
            when(entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor())
                    .thenReturn(Arrays.asList(idpssoDescriptor));
        }
        when(manager.getEntityDescriptor(eq(REALM), eq(entityId))).thenReturn(entityDescriptor);
    }

    private String generateMetadate() {
        StringBuilder builder = new StringBuilder();
        String validUntil = dateFormat.format(metadataExptiration.getTime());
        builder.append(
                "<EntitiesDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"" + validUntil
                        + "\">");
        for (String spEntityId : spInMetadata) {
            builder
                    .append("<EntityDescriptor entityID=\"" + spEntityId + "\">")
                    .append("<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">")
                    .append("<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"DUMMY_URL\" index=\"1\"/>")
                    .append("</SPSSODescriptor>")
                    .append("</EntityDescriptor>");
        }
        for (String idpEntityId : idpInMetadata) {
            builder
                    .append("<EntityDescriptor entityID=\"" + idpEntityId + "\">")
                    .append("<IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">")
                    .append("<SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"DUMMY_URL\"/>")
                    .append("</IDPSSODescriptor>")
                    .append("</EntityDescriptor>");
        }
        builder.append("</EntitiesDescriptor>");
        return builder.toString();
    }

    private void setMetadataExpiration(Calendar validUntil) {
        metadataExptiration = validUntil;
    }

}
