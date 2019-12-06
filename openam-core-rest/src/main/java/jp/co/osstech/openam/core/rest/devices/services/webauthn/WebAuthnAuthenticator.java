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
 * Copyright 2019 Open Source Solution Technology Corporation
 */

package jp.co.osstech.openam.core.rest.devices.services.webauthn;

import java.util.Date;

import org.forgerock.util.encode.Base64url;

/**
 * The WebAuthn Authenticator class.
 */
public class WebAuthnAuthenticator {

    public static String TIMESTAMP_ATTR_NAME = "createTimestamp";

    private String credentialID = null;
    private byte[] publicKey = null;
    private Long signCount = null;
    private byte[] userID = null;
    private String credentialName = null;
    private Date createTimestamp = null;

    /**
     * Default constructor.
     */
    public WebAuthnAuthenticator() {
    }

    /**
     * Basic constructor for WebAuthnAuthenticator.
     * 
     * @param credentialID The Credential ID.
     * @param publicKey The public key.
     * @param signCount The signature counter.
     * @param userID The user handle of the user account entity.
     */
    public WebAuthnAuthenticator(String credentialID, byte[] publicKey, Long signCount,
            byte[] userID) {
        this(credentialID, publicKey, signCount, userID, "Default Credential");
    }

    /**
     * Basic constructor for WebAuthnAuthenticator.
     * 
     * @param credentialID The Credential ID.
     * @param publicKey The public key.
     * @param signCount The signature counter.
     * @param userID The user handle of the user account entity.
     * @param credentailDisplayName The Credential Display Name.
     */
    public WebAuthnAuthenticator(String credentialID, byte[] publicKey, Long signCount,
            byte[] userID, String credentialName) {
        this.credentialID = credentialID;
        this.publicKey = publicKey;
        this.signCount = signCount;
        this.userID = userID;
        this.setCredentialName(credentialName);
    }


    /**
     * Get the Credential ID.
     * 
     * @return The Credential ID.
     */
    public String getCredentialID() {
        return credentialID;
    }

    /**
     * Get hex string of the Credential ID.
     * 
     * @return The hex string of the Credential ID.
     */
    public String getRawCredentialIdAsString() {
        return convBytesArrayToStr(Base64url.decode(credentialID));
    }

    /**
     * Set the Credential ID.
     * 
     * @param credentialID The Credential ID.
     */
    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    /**
     * Get the public key.
     * 
     * @return The public key.
     */
    public byte[] getPublicKey() {
        return publicKey;
    }

    /**
     * Set the public key.
     * 
     * @param publicKey The public key.
     */
    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Get the signature counter.
     * 
     * @return The signature counter.
     */
    public Long getSignCount() {
        return signCount;
    }

    /**
     * Set the signature counter.
     * 
     * @param signCount The signature counter.
     */
    public void setSignCount(Long signCount) {
        this.signCount = signCount;
    }

    /**
     * Get the user handle.
     * 
     * @return The user handle.
     */
    public byte[] getUserID() {
        return userID;
    }

    /**
     * Set the user handle.
     * 
     * @param userID the user handle.
     */
    public void setUserID(byte[] userID) {
        this.userID = userID;
    }

    /**
     * Get the credential display name.
     * 
     * @return credential display name.
     */
    public String getCredentialName() {
        return credentialName;
    }

    /**
     * Set the credential display name.
     * 
     * @param credentail display name.
     */
    public void setCredentialName(String credentialName) {
        this.credentialName = credentialName;
    }

    /**
     * Get the time that the entry was created.
     * 
     * @return The time that the entry was created.
     */
    public Date getCreateTimestamp() {
        return createTimestamp;
    }

    /**
     * Set the time that the entry was created.
     * 
     * @param createTimestamp The time that the entry was created.
     */
    public void setCreateTimestamp(Date createTimestamp) {
        this.createTimestamp = createTimestamp;
    }

    /**
     * Determine if the Credential ID match.
     * 
     * @param credentialID The Credential ID.
     * @return Returns true if the Credential ID matches this authenticator.
     */
    public boolean isSelected(String credentialID) {
        return this.credentialID.equals(credentialID);
    }

    /**
     * Get the userID as a string.
     * 
     * @param userID The user handle.
     * @return the userID as a string.
     */
    public static String getUserIDAsString(byte[] userID) {
        StringBuffer _sb = new StringBuffer();
        for (int i = 0; i < userID.length; i++) {
            _sb.append(Character.toChars(userID[i]));
        }
        return _sb.toString();
    }

    /**
     * Get hex string from byte array.
     * 
     * @param byteArray The byte array.
     * @return The hex string.
     */
    private String convBytesArrayToStr(byte[] byteArray) {
        StringBuilder BytesArrayStr = new StringBuilder();
        for (int i = 0; i < byteArray.length; i++) {
            BytesArrayStr.append(Byte.toUnsignedInt(byteArray[i])).append(",");
        }
        return BytesArrayStr.toString();
    }
}
