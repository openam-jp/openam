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

package jp.co.osstech.openam.authentication.modules.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The POJO for deserializing WebAuthn PublicKeyCredential JSON response.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class WebAuthnJsonCallback {

    private String id;    // String
    private String rawId; // The Base64url encoded byte array
    private String type;  // String
    private String attestationObject; // The Base64url encoded byte array
    private String clientDataJSON;    // The Base64url encoded byte array
    private String authenticatorData; // The Base64url encoded byte array
    private String signature;         // The Base64url encoded byte array
    private String userHandle;        // The Base64url encoded byte array

    /**
     * Base constructor.
     */
    WebAuthnJsonCallback() {
    }

    /**
     * Get the value of PublicKeyCredential.id.
     * @return The value of PublicKeyCredential.id.
     */
    public String getId() {
        return id;
    }

    /**
     * Get the value of PublicKeyCredential.rawId.
     * @return The value of PublicKeyCredential.rawId.
     */
    public String getRawId() {
        return rawId;
    }

    /**
     * Get the value of PublicKeyCredential.type.
     * @return The value of PublicKeyCredential.type.
     */
    public String getType() {
        return type;
    }

    /**
     * Get the value of PublicKeyCredential.response.attestationObject.
     * @return The value of PublicKeyCredential.response.attestationObject.
     */
    public String getAttestationObject() {
        return attestationObject;
    }

    /**
     * Get the value of PublicKeyCredential.response.clientDataJSON.
     * @return The value of PublicKeyCredential.response.clientDataJSON.
     */
    public String getClientDataJSON() {
        return clientDataJSON;
    }

    /**
     * Get the value of PublicKeyCredential.response.attestationObject.
     * @return The value of PublicKeyCredential.response.attestationObject.
     */
    public String getAuthenticatorData() {
        return authenticatorData;
    }

    /**
     * Get the value of PublicKeyCredential.response.signature.
     * @return The value of PublicKeyCredential.response.signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Get the value of PublicKeyCredential.response.userHandle.
     * @return The value of PublicKeyCredential.response.userHandle.
     */
    public String getUserHandle() {
        return userHandle;
    }
}
