package jp.co.osstech.openam.authentication.modules.webauthn;

public class CredentialsCreateOptions {
    private String rpNameConfig;
    private String credentialIdBytesArrayStr; // byte[]
    private String userName;
    private String displayName;
    private String attestationConfig;
    private String attachmentConfig;
    private String residentKeyConfig;
    private String userVerificationConfig;
    private String timeoutConfig;
    private String challengeBytesArrayStr; // byte[]

    CredentialsCreateOptions(
            String rpNameConfig,
            byte[] credentialIdBytesArray, // byte[]
            String userName,
            String displayName,
            String attestationConfig,
            String attachmentConfig,
            String residentKeyConfig,
            String userVerificationConfig,
            String timeoutConfig,
            byte[] challengeBytesArray // byte[]
    ) {
        this.rpNameConfig = rpNameConfig;
        this.credentialIdBytesArrayStr = convBytesArrayToStr(credentialIdBytesArray);
        this.userName = userName;
        this.displayName = displayName;
        this.attestationConfig = attestationConfig;
        this.attachmentConfig = attachmentConfig;
        this.residentKeyConfig = residentKeyConfig;
        this.userVerificationConfig = userVerificationConfig;
        this.timeoutConfig = timeoutConfig;
        this.challengeBytesArrayStr = convBytesArrayToStr(challengeBytesArray);

    }
    
    /*
     * generate secure random byte[]
     * 
     * @param int length
     * 
     * @return StringBuilder "," separated array String.
     */
    private String convBytesArrayToStr(byte[] byteArray) {

        StringBuilder BytesArrayStr = new StringBuilder();

        for (int i = 0; i < byteArray.length; i++) {
            BytesArrayStr.append(Byte.toUnsignedInt(byteArray[i])).append(",");
        }
        return BytesArrayStr.toString();
    }

    /*
     * This function provide
     * getCreateCredntialsScriptCallback(CreateCredentialOptions) 
     */
    public String generateCredntialsCreateScriptCallback() {
        final StringBuilder _credentialCreateScript = new StringBuilder();

        // function (webauthn) start
        _credentialCreateScript
        .append("require([\'jp/co/osstech/openam/server/util/webauthn\'], function (webauthn) { ");
        // webauthn.createCredential start
        _credentialCreateScript.append("webauthn.createCredential(  { ");
        // publicKey start
        _credentialCreateScript.append("publicKey: { ");

        // RP info
        _credentialCreateScript.append("rp: {");
        _credentialCreateScript.append("name: \'");
        _credentialCreateScript.append(rpNameConfig);
        _credentialCreateScript.append("\'");
        _credentialCreateScript.append("}");

        // User info start
        _credentialCreateScript.append(", ");
        _credentialCreateScript.append("user: { ");
        _credentialCreateScript.append("id: new Uint8Array([");
        _credentialCreateScript.append(credentialIdBytesArrayStr);
        _credentialCreateScript.append("])");
        _credentialCreateScript.append(", ");
        _credentialCreateScript.append("name: \'");
        _credentialCreateScript.append(userName);
        _credentialCreateScript.append("\'");
        _credentialCreateScript.append(", ");
        _credentialCreateScript.append("displayName: \'");
        _credentialCreateScript.append(displayName);
        _credentialCreateScript.append("\', ");

        // User info end
        _credentialCreateScript.append("}");

        // Pubkey param
        _credentialCreateScript.append(", ");
        _credentialCreateScript.append("pubKeyCredParams: [{ ");
        _credentialCreateScript.append("type: \'public-key\', ");
        _credentialCreateScript.append("alg: -7");
        _credentialCreateScript.append("}, {");
        _credentialCreateScript.append("type: \'public-key\', ");
        _credentialCreateScript.append("alg: -257 ");
        _credentialCreateScript.append("}]");

        // Attestation
        _credentialCreateScript.append(", ");
        _credentialCreateScript.append("attestation: \'");
        _credentialCreateScript.append(attestationConfig);
        _credentialCreateScript.append("\', ");
        
        // Authenticator Selection
        _credentialCreateScript.append("authenticatorSelection: { ");
        if (!attachmentConfig.equalsIgnoreCase("undefined")) {
            _credentialCreateScript.append("authenticatorAttachment: \'");
            _credentialCreateScript.append(attachmentConfig);
            _credentialCreateScript.append("\', ");
        }
        _credentialCreateScript.append("requireResidentKey: ");
        _credentialCreateScript.append(residentKeyConfig);
        _credentialCreateScript.append(", ");
        _credentialCreateScript.append("userVerification: \'");
        _credentialCreateScript.append(userVerificationConfig);
        _credentialCreateScript.append("\' ");
        _credentialCreateScript.append("}");

        // Timeout
        _credentialCreateScript.append(", ");
        _credentialCreateScript.append("timeout: ");
        _credentialCreateScript.append(timeoutConfig);

        // Challenge
        _credentialCreateScript.append(", ");
        _credentialCreateScript.append("challenge: new Uint8Array([");
        _credentialCreateScript.append(challengeBytesArrayStr);
        _credentialCreateScript.append("])");

        // publickey end
        _credentialCreateScript.append("}");
        // webauthn.createCredential end
        _credentialCreateScript.append("} ); ");
        // function (webauthn) end
        _credentialCreateScript.append("});");
        return _credentialCreateScript.toString();
    }
    
}
