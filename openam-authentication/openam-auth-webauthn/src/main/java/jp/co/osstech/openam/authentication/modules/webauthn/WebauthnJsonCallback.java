package jp.co.osstech.openam.authentication.modules.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)

public class PublicKeyCredentialCallback {

    /*
     * for prototype only
     * todo change private
     * write get value code in this class
     */
    private String id;
    private String rawId;
    private String type;
    private String attestationObject;
    private String clientDataJSON;
    private String CredentialId;
    private String AuthenticatorData;
    private String Signature;
    private String UserHandle;

    PublicKeyCredentialCallback(){

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
        return CredentialId;
    }
    public String getAuthenticatorData() {
        return AuthenticatorData;
    }

    public String getSignature() {
        return Signature;
    }
    public String getUserHandle() {
        return UserHandle;
    }

}
