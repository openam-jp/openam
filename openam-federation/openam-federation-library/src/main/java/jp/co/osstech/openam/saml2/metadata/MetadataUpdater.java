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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;

import javax.xml.bind.JAXBException;

import org.forgerock.util.annotations.VisibleForTesting;
import org.w3c.dom.Document;

import com.sun.identity.saml2.jaxb.metadata.EntitiesDescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.EntityDescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.IDPSSODescriptorElement;
import com.sun.identity.saml2.jaxb.metadata.SPSSODescriptorElement;
import com.sun.identity.saml2.meta.SAML2MetaException;
import com.sun.identity.saml2.meta.SAML2MetaManager;
import com.sun.identity.saml2.meta.SAML2MetaSecurityUtils;
import com.sun.identity.saml2.meta.SAML2MetaUtils;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.xml.XMLUtils;

/**
 * The class <code>MetadataUpdater</code> update the provided metadata with the
 * backup in accordance with given <code>MetadataReloadConfig</code>.
 */
class MetadataUpdater {

    // Used for providing debug messages.
    private static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
    private static final Debug DEBUG = Debug.getInstance(MetadataUpdater.class.getSimpleName());

    private MetadataReloadConfig config;
    private SAML2MetaManager manager;

    /**
     * Constructor.
     *
     * @param config  Configuration of the metadata reload service for the realm.
     * @param manager Instance of <code>SAML2MetaManager</code>.
     */
    MetadataUpdater(MetadataReloadConfig config, SAML2MetaManager manager) {
        this.config = config;
        this.manager = manager;
    }

    /**
     * Update entity configuration by given metadata and backup.
     *
     * @param newMetadata    New metadata.
     * @param backupMetadata Backup (previous) metadata. (optional)
     * @throws JAXBException if an error occurs while converting metadata.
     * @throws MetadataReloadFailureException If an error occurs while processing metadata.
     */
    void update(String newMetadata, Optional<String> backupMetadata) throws JAXBException,MetadataReloadFailureException {
        if (config.shouldValidateSignature() && !signatureValid(newMetadata)) {
            throw new MetadataReloadFailureException("Failed to validate the signature of the metadata.");
        }

        Object obj = SAML2MetaUtils.convertStringToJAXB(newMetadata);

        if (config.shouldCheckExpirationDate() && expired(obj)) {
            throw new MetadataReloadFailureException("Provided metadata is already expired.");
        }

        List<EntityDescriptorElement> newEntities = getAllEntities(obj);

        List<EntityDescriptorElement> backupEntities;
        // In the first time the metadata reload service runs in the server,
        // the backup metadata is null.
        if (backupMetadata.isPresent()) {
            obj = SAML2MetaUtils.convertStringToJAXB(backupMetadata.get());
            backupEntities = getAllEntities(obj);
        } else {
            backupEntities = new ArrayList<>();
        }

        for (EntityDescriptorElement newEntity : newEntities) {
            if (!shouldProcess(newEntity)) {
                DEBUG.message("EntityID: {} is skipped.", newEntity.getEntityID());
                continue;
            }
            try {
                if (alreadyExists(newEntity)) {
                    DEBUG.message("EntityID: {} already exists. It will be updated.", newEntity.getEntityID());
                    manager.setEntityDescriptor(config.realm(), newEntity);
                } else if (config.allowCreateEntities()) {
                    DEBUG.message("EntityID: {} doesn't exist. It will be created.", newEntity.getEntityID());
                    manager.createEntityDescriptor(config.realm(), newEntity);
                } else {
                    DEBUG.message(
                            "EntityID: {} doesn't exist, but it is not allowed to create new entities. It will not be created.",
                            newEntity.getEntityID());
                }
            } catch (SAML2MetaException e) {
                DEBUG.error("Error occurs while creating or updating the entity", e);
                continue;
            }
        }

        for (EntityDescriptorElement backupEntity : backupEntities) {
            try {
                if (isDeleted(backupEntity, newEntities)) {
                    DEBUG.message("EntityID: {} is not included in new metadata. It will be deleted",
                            backupEntity.getEntityID());
                    manager.deleteEntityDescriptor(config.realm(), backupEntity.getEntityID());
                }
            } catch (SAML2MetaException e) {
                DEBUG.error("Error occurs while deleting the entity", e);
                continue;
            }
        }
    }

    private List<EntityDescriptorElement> getAllEntities(Object obj) {
        List<EntityDescriptorElement> answer = new ArrayList<>();

        if (obj instanceof EntityDescriptorElement) {
            answer.add((EntityDescriptorElement) obj);
        } else if (obj instanceof EntitiesDescriptorElement) {
            List elements = ((EntitiesDescriptorElement) obj).getEntityDescriptorOrEntitiesDescriptor();
            for (Object element : elements) {
                answer.addAll(getAllEntities(element));
            }
        }

        return answer;
    }

    private boolean alreadyExists(EntityDescriptorElement entity) throws SAML2MetaException {
        String entityId = entity.getEntityID();
        EntityDescriptorElement current = manager.getEntityDescriptor(config.realm(), entityId);
        return current != null;
    }

    private boolean isDeleted(EntityDescriptorElement backupEntity, List<EntityDescriptorElement> newEntities) {
        String backupEntityId = backupEntity.getEntityID();
        for (EntityDescriptorElement newEntity : newEntities) {
            if (backupEntityId.equals(newEntity.getEntityID())) {
                return false;
            }
        }
        return true;
    }

    private boolean isSP(EntityDescriptorElement entity) {
        Object obj = entity.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().get(0);
        return obj instanceof SPSSODescriptorElement;
    }

    private boolean isIDP(EntityDescriptorElement entity) {
        Object obj = entity.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().get(0);
        return obj instanceof IDPSSODescriptorElement;
    }

    private boolean shouldInclude(EntityDescriptorElement entity) {
        String entityId = entity.getEntityID();
        return config.includeEntities().contains(entityId);
    }

    private boolean shouldExclude(EntityDescriptorElement entity) {
        String entityId = entity.getEntityID();
        return config.excludeEntities().contains(entityId);
    }

    private Calendar getValidUntil(Object obj) {
        if (obj instanceof EntitiesDescriptorElement) {
            return ((EntitiesDescriptorElement) obj).getValidUntil();
        } else {
            return ((EntityDescriptorElement) obj).getValidUntil();
        }
    }

    private boolean expired(Object obj) {
        Calendar validUntil = getValidUntil(obj);
        // If "validUntil" is not set in the metadata, It is considered expired.
        if (validUntil == null) {
            return true;
        }
        DEBUG.message("The metadata is valid until {}.", DATE_FORMAT.format(validUntil.getTime()));

        Calendar now = getCurrent();
        DEBUG.message("Now: {}", DATE_FORMAT.format(now.getTime()));

        if (now.after(validUntil)) {
            return true;
        }
        return false;
    }

    private boolean shouldProcess(EntityDescriptorElement entity) {
        if (shouldExclude(entity)) {
            DEBUG.message("EntityID: {} is in the excluded list. It will be ignored.", entity.getEntityID());
            return false;
        }
        if (shouldInclude(entity)) {
            DEBUG.message("EntityID: {} is in the included list It will be processed", entity.getEntityID());
            return true;
        }
        switch (config.targetRole()) {
            case ALL:
                return true;
            case SP_ONLY:
                return isSP(entity);
            case IDP_ONLY:
                return isIDP(entity);
            case NOTHING:
                return false;
            default:
                return false;
        }
    }

    @VisibleForTesting
    Calendar getCurrent() {
        return Calendar.getInstance();
    }

    @VisibleForTesting
    boolean signatureValid(String metadata) {
        Document document = XMLUtils.toDOMDocument(metadata, DEBUG);
        try {
            SAML2MetaSecurityUtils.verifySignature(document);
            return true;
        } catch (SAML2MetaException e) {
            return false;
        }
    }

}
