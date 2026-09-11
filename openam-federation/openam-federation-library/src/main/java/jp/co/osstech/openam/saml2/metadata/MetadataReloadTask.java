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

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import javax.xml.bind.JAXBException;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import com.sun.identity.common.GeneralTaskRunnable;
import com.sun.identity.common.HttpURLConnectionManager;
import com.sun.identity.shared.debug.Debug;

/**
 * The class <code>MetadataReloadTask</code> reload the metadata and update
 * entity configurations per day.
 */
public class MetadataReloadTask extends GeneralTaskRunnable {

    private static final Debug DEBUG = Debug.getInstance(MetadataReloadTask.class.getSimpleName());

    private String realm;
    private Map<URL, Path> metadataMap;
    private MetadataUpdater updater;
    private MetadataReloadAuditor auditor;

    /**
     * Constructor.
     *
     * @param realm       Realm the task executed for.
     * @param metadataMap Map of URLs and paths. The keys are URL of the metadata
     *                    and the values are path to backup file.
     * @param updater     <code>MetadataUpdater</code> instance.
     * @param auditor     <code>MetadataReloadAuditor</code> instance.
     */
    public MetadataReloadTask(
            String realm,
            Map<URL, Path> metadataMap,
            MetadataUpdater updater,
            MetadataReloadAuditor auditor) {
        this.realm = realm;
        this.metadataMap = metadataMap;
        this.updater = updater;
        this.auditor = auditor;
    }

    @Override
    public boolean addElement(Object key) {
        return false;
    }

    @Override
    public long getRunPeriod() {
        // 1 day
        return 1 * 24 * 60 * 60 * 1000;
    }

    @Override
    public boolean isEmpty() {
        return true;
    }

    @Override
    public boolean removeElement(Object key) {
        return false;
    }

    /**
     * Wrapper of {@link #execute() execute()} used by <code>TimerPool</code>.
     */
    @Override
    public void run() {
        try {
            execute();
        } catch (Exception e) {
            // do nothing
        }
    }

    /**
     * Retireve the metadata and updates configuration, then back up new metadata.
     */
    public void execute() throws Exception {
        Exception thrown = null;

        for (URL metadataURL : metadataMap.keySet()) {
            Path backupPath = metadataMap.get(metadataURL);

            String newMetadata;
            try {
                newMetadata = getMetadataFrmoURL(metadataURL);
            } catch (IOException e) {
                DEBUG.error("Can't retrieve a new metadata", e);
                thrown = e;
                continue;
            }

            Optional<String> backupMetadata;
            try {
                backupMetadata = getBackupFromPath(backupPath);
            } catch (IOException e) {
                DEBUG.error("Can't retrieve a backup metadata.", e);
                thrown = e;
                continue;
            }

            try {
                updater.update(newMetadata, backupMetadata);
                storeBackup(newMetadata, backupPath);
            } catch (IOException e) {
                DEBUG.error("An error occurs while storing backup. Path: " + backupPath.toString(), e);
                thrown = e;
            } catch (JAXBException e) {
                DEBUG.error("An error occurs while parsing metadata. URL: " + metadataURL.toString(), e);
                thrown = e;
            } catch (MetadataReloadFailureException e) {
                DEBUG.error("An error occurs while processing metadata. URL: " + metadataURL.toString(), e);
                thrown = e;
            }
        }

        if (thrown != null) {
            auditor.auditError(realm);
            throw thrown;
        }
        auditor.auditComplete(realm);
    }

    private String getMetadataFrmoURL(URL url) throws IOException {
        HttpURLConnection connection = HttpURLConnectionManager.getConnection(url);
        connection.setRequestMethod("GET");
        connection.setDoOutput(true);
        return IOUtils.toString(connection.getInputStream());
    }

    private Optional<String> getBackupFromPath(Path path) throws IOException {
        try {
            return Optional.of(new String(Files.readAllBytes(path), Charsets.UTF_8));
        } catch (NoSuchFileException e) {
            // When this task is executed for the first time,
            // backup metadata file does not exists. At this time,
            // <code>NoSuchFileException</code> is thrown.
            DEBUG.message("Backup metadata is not found. " + e.getMessage());
            return Optional.empty();
        }
    }

    private void storeBackup(String metadata, Path backupPath) throws IOException {
        File backupFile = backupPath.toFile();
        File parentDirectory = backupFile.getParentFile();
        if (parentDirectory != null && !parentDirectory.exists()) {
            throw new IOException("Parent directory: " + parentDirectory.getAbsolutePath() + " does not exist.");
        }
        FileUtils.write(backupFile, metadata, Charsets.UTF_8, false);
    }

}
