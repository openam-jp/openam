package jp.co.osstech.openam.authentication.modules.webauthn;

import java.util.Base64;

public class CredentialsGetOptions {
    private String credentialIdBytesArrayStr; // byte[]
    private String userVerificationConfig;
    private String challengeBytesArrayStr; // byte[]
    private String timeoutConfig;
    private String residentKeyConfig;
    

    CredentialsGetOptions(
            String credentialIdBase64,
            String userVerificationConfig,
            byte[] challengeBytesArray, // byte[]
            String timeoutConfig,
            String residentKeyConfig
    ) {
        this.credentialIdBytesArrayStr = convBytesArrayToStr(Base64.getDecoder().decode(credentialIdBase64));
        this.userVerificationConfig = userVerificationConfig;
        this.challengeBytesArrayStr = convBytesArrayToStr(challengeBytesArray);
        this.timeoutConfig = timeoutConfig;
        this.residentKeyConfig = residentKeyConfig;
    }

    CredentialsGetOptions(
            byte[] credentialIdBytesArray, // byte[],
            String userVerificationConfig,
            byte[] challengeBytesArray, // byte[]
            String timeoutConfig,
            String regidentKeyConfig
    ) {
        this.credentialIdBytesArrayStr = convBytesArrayToStr(credentialIdBytesArray);
        this.userVerificationConfig = userVerificationConfig;
        this.challengeBytesArrayStr = convBytesArrayToStr(challengeBytesArray);
        this.timeoutConfig = timeoutConfig;
        this.residentKeyConfig = regidentKeyConfig;
    }
    
    CredentialsGetOptions(
            String userVerificationConfig,
            byte[] challengeBytesArray, // byte[]
            String timeoutConfig,
            String regidentKeyConfig
    ) {
        this.credentialIdBytesArrayStr = "";
        this.userVerificationConfig = userVerificationConfig;
        this.challengeBytesArrayStr = convBytesArrayToStr(challengeBytesArray);
        this.timeoutConfig = timeoutConfig;
        this.residentKeyConfig = regidentKeyConfig;
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
    public String generateCredntialsGetScriptCallback() {
        final StringBuilder _credentialGetScript = new StringBuilder();

        _credentialGetScript.append("require([\'jp/co/osstech/openam/server/util/webauthn\'], function (webauthn) { ");
        _credentialGetScript.append("webauthn.getCredential(  { ");
        _credentialGetScript.append("publicKey: {");

        // AllowCredentials
        _credentialGetScript.append("allowCredentials: [ {");
        _credentialGetScript.append("type: \'public-key\'");
        if ( !residentKeyConfig.equalsIgnoreCase("true")) {
        _credentialGetScript.append(", ");
        _credentialGetScript.append("id: new Uint8Array([");
        _credentialGetScript.append(credentialIdBytesArrayStr);
        _credentialGetScript.append("])");
        }
        _credentialGetScript.append(", ");
        _credentialGetScript.append("transports: [");
        _credentialGetScript.append("\'usb\', ");
        _credentialGetScript.append("\'nfc\', ");
        _credentialGetScript.append("\'ble\', ");
        _credentialGetScript.append("\'internal\'");
        _credentialGetScript.append("]");
        _credentialGetScript.append("} ]");

        // UserVerification
        _credentialGetScript.append(", ");
        _credentialGetScript.append("   userVerification: \'");
        _credentialGetScript.append(userVerificationConfig);
        _credentialGetScript.append("\'");

        // Challenge
        _credentialGetScript.append(", ");
        _credentialGetScript.append("challenge: new Uint8Array([");
        _credentialGetScript.append(challengeBytesArrayStr);
        _credentialGetScript.append("])");
        
        // Timeout
        _credentialGetScript.append(", ");
        _credentialGetScript.append("timeout: ");
        _credentialGetScript.append(timeoutConfig);

        // publickey end
        _credentialGetScript.append("} ");
        // webauthn.getCredential end
        _credentialGetScript.append("} );");
        // function (webauthn) end
        _credentialGetScript.append("});");
        return _credentialGetScript.toString();

    }
}
