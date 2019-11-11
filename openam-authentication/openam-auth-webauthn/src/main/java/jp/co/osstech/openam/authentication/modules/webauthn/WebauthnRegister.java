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

import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.sm.SMSException;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplanet.sso.SSOException;

import org.forgerock.openam.utils.StringUtils;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

/**
 * WebAuthn (Register) Authentication Module.
 */
public class WebauthnRegister extends AbstractWebAuthnModule {

    public static final String BUNDLE_NAME = "amAuthWebauthnRegister";
    private static final Debug DEBUG = Debug.getInstance(WebauthnRegister.class.getSimpleName());
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Module States
    private final int STATE_COMPLETE = -1;
    private final int STATE_REG_START = 1;
    private final int STATE_REG_SCRIPT = 2;
    private final int STATE_REG_KEY = 3;
    
    // Configuration Strings for Register
    private static final String ATTESTATION = "iplanet-am-auth-Webauthn-attestation";
    private static final String ATTACHMENT = "iplanet-am-auth-Webauthn-attachment";
    
    // Configuration Parameters for Register
    private String attestationConfig = "";
    private String attachmentConfig = "";
    
    // Webauthn
    private byte[] userHandleIdBytes;
    private WebAuthnAuthenticator attestedAuthenticator;

    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("WebauthnRegister module init start");
        }
        
        super.init(subject, sharedState, options);
        
        this.attestationConfig = CollectionHelper.getMapAttr(options, ATTESTATION);
        this.attachmentConfig = CollectionHelper.getMapAttr(options, ATTACHMENT);

        if (DEBUG.messageEnabled()) {
            DEBUG.message("WebauthnRegister module parameter are " 
                    + "authLevel = " + authLevel
                    + ", rpName = " + rpNameConfig
                    + ", origin = " + originConfig 
                    + ", attestation = " + attestationConfig
                    + ", attachment = " + attachmentConfig 
                    + ", residentKey = " + residentKeyConfig
                    + ", userVerification = " + userVerificationConfig 
                    + ", timeoutConfig = " + timeoutConfig
                    + ", displayNameAttributeName = " + displayNameAttributeNameConfig);
        }
        
        userName = (String) sharedState.get(getUserKey());
        if (StringUtils.isEmpty(userName)) {
            try {
                userName = getUserSessionProperty(ISAuthConstants.USER_TOKEN);
            } catch (AuthLoginException e) {
                DEBUG.message("WebauthnRegister.init() : Cannot lookup userName from shared State.");
            }
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message("WebauthnRegister.init() : userName is " + userName);
        }
    }

    @Override
    public int process(Callback[] callbacks, int state) throws AuthLoginException {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("WebauthnRegister.process() : login state is " + state);
        }

        int nextState;

        switch (state) {

        case STATE_REG_START:
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebauthnRegister.process() : This state is REG_START.");
            }
            nextState = createScript(callbacks);
            break;
        case STATE_REG_SCRIPT:
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebauthnRegister.process() : This state is REG_SCRIPT.");
            }
            nextState = storeAuthenticator(callbacks);
            break;
        case STATE_REG_KEY:
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebauthnRegister.process() : This state is REG_KEY.");
            }
            nextState = storeCredentialName(callbacks);
            break;
        default:
            DEBUG.error("WebauthnRegister.process() : Invalid module state.");
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }

        return nextState;
    }
    
    /**
     * Create javascript create.credential.
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private int createScript(Callback[] callbacks) 
            throws AuthLoginException {
        
        int nextState;
        
        if (userName != null) {
            nextState = STATE_REG_SCRIPT;
        } else {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
        
        // if Cancel Button Return Authentication Fail
        if (((ConfirmationCallback)callbacks[0]).getSelectedIndex() == 1) {
            throw new AuthLoginException("Ragistration Cancel Auth Fail");
        }

        // Generate challenge
        byte[] _challengeBytes = webauthnValidator.generateChallenge();

        // Use LDAP entryUUID as userHandleId
        userHandleIdBytes = lookupByteData("entryUUID");

        // Replace Callback to send Generated Javascript that include create options.
        // only for nextState REG_SCRIPT
        Callback creadentialsCreateCallback = 
                ScriptCallbackGenerator.generateCredntialsCreateScriptCallback(
                        rpNameConfig,
                        userHandleIdBytes,
                        userName,
                        lookupStringData(displayNameAttributeNameConfig),
                        attestationConfig,
                        attachmentConfig,
                        residentKeyConfig,
                        userVerificationConfig,
                        timeoutConfig,
                        _challengeBytes);
        replaceCallback(STATE_REG_SCRIPT, 0, creadentialsCreateCallback);
        
        return nextState;
    }

    /**
     * Verify the response of javascript credential.create and store the authenticator.
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private int storeAuthenticator(Callback[] callbacks) 
            throws AuthLoginException {
        
        int nextState;
        
        // if Cancel Button Return Authentication Fail
        if (((ConfirmationCallback)callbacks[2]).getSelectedIndex() == 1) {
            throw new AuthLoginException("Ragistration Cancel Auth Fail");
        }

        // read HiddenValueCallback from Authenticator posted
        String _webauthnHiddenCallback = ((HiddenValueCallback) callbacks[1]).getValue();
        if (StringUtils.isEmpty(_webauthnHiddenCallback)) {
            DEBUG.error("WebauthnRegister.storeAuthenticator() : webauthnHiddenCallback is empty");
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }

        if (DEBUG.messageEnabled()) {
            DEBUG.message("Posted webauthnHiddenCallback = " + _webauthnHiddenCallback);
        }

        WebauthnJsonCallback _responseJson;
        try {
            _responseJson = OBJECT_MAPPER.readValue(_webauthnHiddenCallback,
                    WebauthnJsonCallback.class);
            if (DEBUG.messageEnabled()) {
                DEBUG.message("id Base64url = " + _responseJson.getId());
            }
        } catch (IOException e) {
            DEBUG.error("WebauthnRegister.storeAuthenticator(): JSON parse error", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        }

        attestedAuthenticator = webauthnValidator.validateCreateResponse(
                getValidationConfig(), _responseJson, userHandleIdBytes, DEBUG);

        try {
            String realm = DNMapper.orgNameToRealmName(getRequestOrg());
            webauthnService = webauthnServiceFactory.create(realm);
            boolean _storeResult = webauthnService.createAuthenticator(attestedAuthenticator);
            
            if (_storeResult) {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("WebauthnRegister.storeAuthenticator() was success");
                }
                nextState = STATE_REG_KEY;
            } else {
                DEBUG.error("WebauthnRegister.storeAuthenticator() was Fail");
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
        } catch (SSOException | SMSException e) {
            DEBUG.error("WebauthnRegister.storeAuthenticator() : Webauthn module exception : ", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
        
        return nextState;
    }
    
    /**
     * Store CredentialName.
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private int storeCredentialName(Callback[] callbacks) 
            throws AuthLoginException {
        
        int nextState;
        
        String credentialname = ((NameCallback) callbacks[1]).getName();
        if (StringUtils.isNotEmpty(credentialname)) {
            attestedAuthenticator.setCredentialName(credentialname);

            boolean _storeResult = false;
            _storeResult = webauthnService.storeCredentialName(attestedAuthenticator);
            if (_storeResult) {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("WebauthnRegister.storeCredentialName() was success");
                }
                nextState = STATE_COMPLETE;
            } else {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("WebauthnRegister.storeCredentialName() was Fail");
                }
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
        } else {
            nextState = STATE_COMPLETE;
        }
        return nextState;
    }

    @Override
    protected Debug getDebugInstance() {
        return DEBUG;
    }
    
    @Override
    protected String getBundleName() {
        return BUNDLE_NAME;
    }
}
