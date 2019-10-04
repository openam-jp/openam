package jp.co.osstech.openam.authentication.modules.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)

public class WebauthnJsonCallback {

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

    WebauthnJsonCallback() {

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
