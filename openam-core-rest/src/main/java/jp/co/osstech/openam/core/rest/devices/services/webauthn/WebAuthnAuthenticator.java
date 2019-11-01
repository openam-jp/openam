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

import java.util.Base64;

import org.forgerock.util.encode.Base64url;

public class WebAuthnAuthenticator {
    
    private String credentialID = null;
    private byte[] publicKey = null;
    private Long signCount = null;
    private byte[] userID = null;
    
    public WebAuthnAuthenticator() {
    }
    
    public WebAuthnAuthenticator(String credentialID, byte[] publicKey, Long signCount,
            byte[] userID) {
        this.credentialID = credentialID;
        this.publicKey = publicKey;
        this.signCount = signCount;
        this.userID = userID;
    }

    public String getCredentialID() {
        return credentialID;
    }
    
    public String getRawCredentialIdAsString() {
        return convBytesArrayToStr(Base64url.decode(credentialID));
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public Long getSignCount() {
        return signCount;
    }

    public void setSignCount(Long signCount) {
        this.signCount = signCount;
    }

    public byte[] getUserID() {
        return userID;
    }

    public void setUserID(byte[] userID) {
        this.userID = userID;
    }
    
    public boolean isSelected(String credentialID) {
        return this.credentialID.equals(credentialID);
    }
    
    static String getUserIDAsString(byte[] userID) {
        StringBuffer _sb = new StringBuffer();
        for (int i = 0; i < userID.length; i++) {
            _sb.append( Character.toChars(userID[i]) );
        }
        return _sb.toString();
    }
    
    private String convBytesArrayToStr(byte[] byteArray) {

        StringBuilder BytesArrayStr = new StringBuilder();

        for (int i = 0; i < byteArray.length; i++) {
            BytesArrayStr.append(Byte.toUnsignedInt(byteArray[i])).append(",");
        }
        return BytesArrayStr.toString();
    }
    
    
}
