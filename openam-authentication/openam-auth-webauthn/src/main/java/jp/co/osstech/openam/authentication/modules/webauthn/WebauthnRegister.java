/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2018 Open Source Solution Technology,Corp.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * 
 *
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

import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.iplanet.sso.SSOException;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.devices.services.AuthenticatorDeviceServiceFactory;
import org.forgerock.openam.utils.StringUtils;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnService;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnServiceFactory;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

/**
 * WebAuthn (Register) Authentication Module.
 */
public class WebauthnRegister extends AbstractWebAuthnModule {

    public static final String BUNDLE_NAME = "amAuthWebauthnRegister";
    private static final Debug DEBUG = Debug.getInstance(WebauthnRegister.class.getSimpleName());
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Configuration Strings for Register
    private static final String ATTESTATION = "iplanet-am-auth-Webauthn-attestation";
    private static final String ATTACHMENT = "iplanet-am-auth-Webauthn-attachment";
    
    // Configuration Parameters for Register
    private String attestationConfig = "";
    private String attachmentConfig = "";
    
    // Webauthn
    private byte[] userHandleIdBytes;
    private WebAuthnAuthenticator attestedAuthenticator;
    private final AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService> webauthnServiceFactory =
            InjectorHolder.getInstance(Key.get(
                    new TypeLiteral<AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService>>(){},
                    Names.named(AuthenticatorWebAuthnServiceFactory.FACTORY_NAME)));
    private AuthenticatorWebAuthnService webauthnService;
    private WebAuthnValidator webauthnValidator = new WebAuthn4JValidatorImpl();
    
    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("Webauthn module init start");
        }
        
        super.init(subject, sharedState, options);
        
        this.attestationConfig = CollectionHelper.getMapAttr(options, ATTESTATION);
        this.attachmentConfig = CollectionHelper.getMapAttr(options, ATTACHMENT);

        if (DEBUG.messageEnabled()) {
            DEBUG.message("Webauthn module parameter are " 
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
                DEBUG.message("Webauthn::init: Cannot lookup userName from shared State.");
            }
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message("userName: " + userName);
        }
    }

    @Override
    public int process(Callback[] callbacks, int state) throws AuthLoginException {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("in process(), login state is " + state);
        }

        WebauthnRegisterModuleState moduleState = WebauthnRegisterModuleState.get(state);
        WebauthnRegisterModuleState nextState = null;

        switch (moduleState) {

        case REG_START:
            nextState = createScript(callbacks);
            break;
        case REG_SCRIPT:
            nextState = storeAuthenticator(callbacks);
            break;
        case REG_KEY:
            nextState = storeCredentialName(callbacks);
            break;
        default:
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }

        return nextState.intValue();
    }
    
    /**
     * Create javascript create.credential.
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private WebauthnRegisterModuleState createScript(Callback[] callbacks) 
            throws AuthLoginException {
        
        WebauthnRegisterModuleState nextState;
        
        if (DEBUG.messageEnabled()) {
            DEBUG.message("ThisState = WebauthnRegisterModuleState.REG_START");
        }

        if (userName != null) {
            nextState = WebauthnRegisterModuleState.REG_SCRIPT;
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

        // navigator.credentials.create Options
        CredentialsCreateOptions credentialsCreateOptions = 
                new CredentialsCreateOptions(
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

        // Replace Callback to send Generated Javascript that include create options.
        // only for nextState REG_SCRIPT
        Callback creadentialsCreateCallback = new ScriptTextOutputCallback(
                credentialsCreateOptions.generateCredntialsCreateScriptCallback());
        replaceCallback(WebauthnRegisterModuleState.REG_SCRIPT.intValue(), 0, creadentialsCreateCallback);
        
        return nextState;
    }

    /**
     * Verify the response of javascript credential.create and store the authenticator.
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private WebauthnRegisterModuleState storeAuthenticator(Callback[] callbacks) 
            throws AuthLoginException {
        
        WebauthnRegisterModuleState nextState;
        
        if (DEBUG.messageEnabled()) {
            DEBUG.message("ThisState = WebauthnRegisterModuleState.REG_SCRIPT");
        }

        // read HiddenValueCallback from Authenticator posted
        String _webauthnHiddenCallback = ((HiddenValueCallback) callbacks[1]).getValue();
        // TODO: Cancel
        if (StringUtils.isEmpty(_webauthnHiddenCallback)) {
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
            DEBUG.error("Webauthn.process(): JSON parse error", e);
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
                    DEBUG.message("storeCredentials was success");
                }
                nextState = WebauthnRegisterModuleState.REG_KEY;
            } else {
                DEBUG.error("storeCredentials was Fail");
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
        } catch (SSOException | SMSException e) {
            DEBUG.error("Webauthn.storeCredentials : Webauthn module exception : ", e);
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
    private WebauthnRegisterModuleState storeCredentialName(Callback[] callbacks) 
            throws AuthLoginException {
        
        WebauthnRegisterModuleState nextState;
        // TODO user enter credential nick name and store it at this state.
        if (DEBUG.messageEnabled()) {
            DEBUG.message("ThisState = WebauthnRegisterModuleState.REG_KEY");
        }
        
        String credentialname = ((NameCallback) callbacks[1]).getName();
        if (StringUtils.isNotEmpty(credentialname)) {
            attestedAuthenticator.setCredentialName(credentialname);

            boolean _storeResult = false;
            _storeResult = webauthnService.storeCredentialName(attestedAuthenticator);
            if (_storeResult) {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("storeCredentialName was success");
                }
                nextState = WebauthnRegisterModuleState.COMPLETE;
            } else {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("storeCredentialName was Fail");
                }
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
        } else {
            nextState = WebauthnRegisterModuleState.COMPLETE;
        }
        return nextState;
    }
    
    @Override
    public void destroyModuleState() {
        validatedUserID = null;
    }

    @Override
    public void nullifyUsedVars() {
        bundle = null;
        userName = null;
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
