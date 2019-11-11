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

import java.util.Set;

import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

/**
 * The class generate ScriptCallback for WebAuthn API. 
 */
public class ScriptCallbackGenerator {

    /**
     * This function provide ScriptCallback for WebAuthn credentials.create().
     * 
     * @param rpNameConfig The RP name.
     * @param userHandleIdBytesArray The byte array of user handle.
     * @param userName The user name.
     * @param displayName The user display name.
     * @param attestationConfig The configuration for attestation.
     * @param attachmentConfig The configuration for attachment.
     * @param residentKeyConfig The configuration for resident key.
     * @param userVerificationConfig The configuration for user verification.
     * @param timeoutConfig The configuration for timeout.
     * @param challengeBytesArray The byte array of challenge.
     * @return ScriptCallback for WebAuthn credentials.create().
     */
    public static ScriptTextOutputCallback generateCredntialsCreateScriptCallback (
            String rpNameConfig,
            byte[] userHandleIdBytesArray,
            String userName,
            String displayName,
            String attestationConfig,
            String attachmentConfig,
            String residentKeyConfig,
            String userVerificationConfig,
            String timeoutConfig,
            byte[] challengeBytesArray) {
        
        String _userHandleIdBytesArrayStr = convBytesArrayToStr(userHandleIdBytesArray);
        String _challengeBytesArrayStr = convBytesArrayToStr(challengeBytesArray);
        
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
        _credentialCreateScript.append(_userHandleIdBytesArrayStr);
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
        _credentialCreateScript.append(_challengeBytesArrayStr);
        _credentialCreateScript.append("])");

        // publickey end
        _credentialCreateScript.append("}");
        // webauthn.createCredential end
        _credentialCreateScript.append("} ); ");
        // function (webauthn) end
        _credentialCreateScript.append("});");
        return new ScriptTextOutputCallback(_credentialCreateScript.toString());
    }
    
    /**
     * This function provide ScriptCallback for WebAuthn credentials.get().
     * 
     * @param authenticators The Authenticators
     * @param residentKeyConfig The configuration for resident key.
     * @param userVerificationConfig The configuration for user verification.
     * @param timeoutConfig The configuration for timeout.
     * @param challengeBytesArray The byte array of challenge.
     * @return ScriptCallback for WebAuthn credentials.get().
     */
    public static ScriptTextOutputCallback generateCredntialsGetScriptCallback (
            Set<WebAuthnAuthenticator> authenticators,
            String residentKeyConfig,
            String userVerificationConfig,
            String timeoutConfig,
            byte[] challengeBytesArray) {
        
        String _challengeBytesArrayStr = convBytesArrayToStr(challengeBytesArray);
        
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
        _credentialGetScript.append(_challengeBytesArrayStr);
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
        return new ScriptTextOutputCallback(_credentialGetScript.toString());
    }
    
    /**
     * Get hex string from byte array.
     *
     * @param byteArray The byte array.
     * @return The hex string.
     */
    private static String convBytesArrayToStr(byte[] byteArray) {
        StringBuilder BytesArrayStr = new StringBuilder();
        for (int i = 0; i < byteArray.length; i++) {
            BytesArrayStr.append(Byte.toUnsignedInt(byteArray[i])).append(",");
        }
        return BytesArrayStr.toString();
    }
}
