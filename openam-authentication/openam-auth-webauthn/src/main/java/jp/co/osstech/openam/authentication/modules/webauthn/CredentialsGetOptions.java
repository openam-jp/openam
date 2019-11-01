package jp.co.osstech.openam.authentication.modules.webauthn;

import java.util.Base64;
import java.util.Set;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

public class CredentialsGetOptions {
    //private String credentialIdBytesArrayStr; // byte[]
    private Set<WebAuthnAuthenticator> authenticators;
    private String userVerificationConfig;
    private String challengeBytesArrayStr; // byte[]
    private String timeoutConfig;
    private String residentKeyConfig;

    CredentialsGetOptions(
            Set<WebAuthnAuthenticator> authenticators,
            String userVerificationConfig,
            byte[] challengeBytesArray, // byte[]
            String timeoutConfig,
            String residentKeyConfig
    ) {
        this.authenticators = authenticators;
        this.userVerificationConfig = userVerificationConfig;
        this.challengeBytesArrayStr = convBytesArrayToStr(challengeBytesArray);
        this.timeoutConfig = timeoutConfig;
        this.residentKeyConfig = residentKeyConfig;
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
        
        if (residentKeyConfig.equalsIgnoreCase("false")) {
            // AllowCredentials
            _credentialGetScript.append("allowCredentials: [ ");
            int size = 0;
            for (WebAuthnAuthenticator authenticator: authenticators) {
                _credentialGetScript.append("{type: \'public-key\'");
                _credentialGetScript.append(", ");
                _credentialGetScript.append("id: new Uint8Array([");
                _credentialGetScript.append(authenticator.getRawCredentialIdAsString());
                _credentialGetScript.append("])");
                _credentialGetScript.append(", ");
                _credentialGetScript.append("transports: [");
                _credentialGetScript.append("\'usb\', ");
                _credentialGetScript.append("\'nfc\', ");
                _credentialGetScript.append("\'ble\', ");
                _credentialGetScript.append("\'internal\'");
                _credentialGetScript.append("] }");
                if (++size <= authenticators.size()) {
                    _credentialGetScript.append(",");
                }
            }
            _credentialGetScript.append(" ]");
            _credentialGetScript.append(", ");
        }
        // UserVerification
        _credentialGetScript.append("userVerification: \'");
        _credentialGetScript.append(userVerificationConfig);
        _credentialGetScript.append("\'");
        _credentialGetScript.append(", ");

        // Challenge
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
