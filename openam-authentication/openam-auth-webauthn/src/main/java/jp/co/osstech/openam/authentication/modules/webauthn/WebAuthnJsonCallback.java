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

@JsonIgnoreProperties(ignoreUnknown = true)

public class WebAuthnJsonCallback {

    /*
     * for prototype only todo change private write get value code in this class
     */
    private String id; // base64url String
    private String rawId; // base64 or byte[]
    private String type;
    private String attestationObject; // base64 or byte[]
    private String clientDataJSON; // base64 or byte[]
    private String credentialId; // base64 or byte[]
    private String authenticatorData; // base64 or byte[]
    private String signature; // base64 or byte[]
    private String userHandle;

    WebAuthnJsonCallback() {

    }

    public String getId() {
        return id;
    }

    public String getRawId() {
        return rawId;
    }

    public String getType() {
        return type;
    }

    public String getAttestationObject() {
        return attestationObject;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public String getSignature() {
        return signature;
    }

    public String getUserHandle() {
        return userHandle;
    }

}
