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

/**
 *
 * @author tonoki
 */
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;

import java.io.IOException;
import java.util.Map;
import java.util.Base64;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.devices.services.AuthenticatorDeviceServiceFactory;
import org.forgerock.openam.utils.StringUtils;

import com.webauthn4j.converter.util.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnService;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnServiceFactory;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

public class WebauthnRegister extends AbstractWebAuthnModule {

    private static final String BUNDLE_NAME = "amAuthWebauthnRegister";
    private final static Debug DEBUG = Debug.getInstance(WebauthnRegister.class.getSimpleName());

    // Configuration Strings for Register
    private static final String ATTESTATION = "iplanet-am-auth-Webauthn-attestation";
    private static final String ATTACHMENT = "iplanet-am-auth-Webauthn-attachment";
    
    // Configuration Parameters for Register
    private String attestationConfig = "";
    private String attachmentConfig = "";
    
    // Webauthn Credentials
    private byte[] userHandleIdBytes;
    private byte[] attestedCredentialIdBytes;
    private Challenge generatedChallenge;
    private CredentialPublicKey attestedCredentialPublicKey;
    private byte[] challengeBytes;
    private String webauthnHiddenCallback;
    private byte[] attestationObjectBytes;
    private byte[] clientDataJsonBytes;
    private boolean verificationRequired;
    private long attestedCounter;
    private WebAuthnAuthenticator attestedAuthenticator;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
    private final AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService> webauthnServiceFactory =
            InjectorHolder.getInstance(Key.get(
                    new TypeLiteral<AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService>>(){},
                    Names.named(AuthenticatorWebAuthnServiceFactory.FACTORY_NAME)));
    private AuthenticatorWebAuthnService webauthnService;
    
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

            // generate 16byte challenge
            // generate 16byte id
            generatedChallenge = new DefaultChallenge();
            challengeBytes = ArrayUtil.clone(generatedChallenge.getValue());


            /*
             * Use LDAP entryUUID as userHandleId
             * 
             */
            //ByteBuffer _bb = ByteBuffer.wrap(lookupByteData("entryUUID"));
            //userHandleIdBytes = _bb.array();
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
                    challengeBytes);

            // Replace Callback to send Generated Javascript that include create options.
            // only for nextState REG_SCRIPT
            Callback creadentialsCreateCallback = new ScriptTextOutputCallback(
                    credentialsCreateOptions.generateCredntialsCreateScriptCallback());
            replaceCallback(WebauthnRegisterModuleState.REG_SCRIPT.intValue(), 0, creadentialsCreateCallback);

            break;

        case REG_SCRIPT:

            if (DEBUG.messageEnabled()) {
                DEBUG.message("ThisState = WebauthnRegisterModuleState.REG_SCRIPT");
            }

            // Registration Verify PublicKey Credentials
            // expect REG_KEY
            try {
                nextState = verifyRegisterCallback(callbacks);
            } catch (AuthLoginException ex) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
            }

            break;

        case REG_KEY:
            // TODO user enter credential nick name and store it at this state.
            if (DEBUG.messageEnabled()) {
                DEBUG.message("ThisState = WebauthnRegisterModuleState.REG_KEY");
            }
            
            try {
                nextState = storeCredentialNameCallback(callbacks);
            } catch (Exception ex) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
            }
            // only display next button and return LOGIN_START
            //nextState = WebauthnRegisterModuleState.COMPLETE;

            break;

        }

        return nextState.intValue();
    }

    /*
     * Verify and Store Authenticator(browser) Response Credentials for Registration
     * @param callbacks an array of <code>Callback</cdoe> for this Login state
     * @return int order of next state. Return
     * @throws AuthLoginException
     */
    private WebauthnRegisterModuleState verifyRegisterCallback(Callback[] callbacks) throws AuthLoginException {

        // read HiddenValueCallback from Authenticator posted
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof HiddenValueCallback) {
                webauthnHiddenCallback = ((HiddenValueCallback) callbacks[i]).getValue();

                if (webauthnHiddenCallback == null) {
                    return WebauthnRegisterModuleState.REG_START;
                }

            }
        }

        if (DEBUG.messageEnabled()) {
            DEBUG.message("Posted webauthnHiddenCallback = " + webauthnHiddenCallback);
        }

        /*
         * Map Callback to Object
         */
        if (StringUtils.isNotEmpty(webauthnHiddenCallback)) {

            try {
                WebauthnJsonCallback _responseJson = OBJECT_MAPPER.readValue(webauthnHiddenCallback,
                        WebauthnJsonCallback.class);

                if (DEBUG.messageEnabled()) {
                    DEBUG.message("id Base64url = " + _responseJson.getId());
                }

                attestationObjectBytes = Base64.getDecoder().decode(_responseJson.getAttestationObject());
                clientDataJsonBytes = Base64.getDecoder().decode(_responseJson.getClientDataJSON());

            } catch (IOException e) {
                DEBUG.error("Webauthn.process(): JSON parse error", e);
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
            }
        }

        /*
         * Validation authenticator response This must be change to W3C verification
         * flow. This time use webauthn4j library to END
         * START============================.
         */
        Origin _origin = new Origin(originConfig);
        String _rpId = _origin.getHost();

        byte[] _tokenBindingId = null;
        if (userVerificationConfig.equalsIgnoreCase("required")) {
            verificationRequired = true;
        } else {
            verificationRequired = false;
        }
        // rp:id = origin
        ServerProperty serverProperty = new ServerProperty(_origin, _rpId, generatedChallenge, _tokenBindingId);

        try {
            WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(clientDataJsonBytes,
                    attestationObjectBytes, serverProperty, verificationRequired);
            WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator = WebAuthnRegistrationContextValidator
                    .createNonStrictRegistrationContextValidator();
            WebAuthnRegistrationContextValidationResponse response = webAuthnRegistrationContextValidator
                    .validate(registrationContext);

            // CredentialId <-- AttestedCredentialData <--AuthenticationData
            // <--AttestationObject
            attestedCredentialIdBytes = ArrayUtil.clone(response.getAttestationObject().getAuthenticatorData()
                    .getAttestedCredentialData().getCredentialId());

            // PublicKey(COSE) <-- AttestedCredentialData <--AuthenticationData
            // <--AttestationObject
            attestedCredentialPublicKey = response.getAttestationObject().getAuthenticatorData()
                    .getAttestedCredentialData().getCredentialPublicKey();

            // Counter <--AuthenticationData <--AttestationObject
            attestedCounter = response.getAttestationObject().getAuthenticatorData().getSignCount();

        } catch (Exception ex) {
            DEBUG.error("Webauthn.webauthn4j.verify() : Webauthn4j exception : ", ex);
        }
        /*
         * END of webauthn4j library line END============================
         */

        try {
            // boolean _storeResult
            boolean _storeResult = false;
            
            CborConverter _cborConverter = new CborConverter();
            String realm = DNMapper.orgNameToRealmName(getRequestOrg());
            webauthnService = webauthnServiceFactory.create(realm);
            attestedAuthenticator = new WebAuthnAuthenticator(
                    Base64UrlUtil.encodeToString(attestedCredentialIdBytes),
                    _cborConverter.writeValueAsBytes(attestedCredentialPublicKey),
                    new Long(attestedCounter), userHandleIdBytes);
            _storeResult = webauthnService.createAuthenticator(attestedAuthenticator);
            
            if (_storeResult) {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("storeCredentials was success");
                }
                return WebauthnRegisterModuleState.REG_KEY;

            } else {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("storeCredentials was Fail");
                }
                return WebauthnRegisterModuleState.REG_START;

            }
        } catch (Exception e) {
            DEBUG.error("Webauthn.storeCredentials : Webauthn module exception : ", e);
            return WebauthnRegisterModuleState.REG_START;
        }
    }
    
    /*
     * Store Authenticator(browser) Response Credentials for Registration
     * @param callbacks an array of <code>Callback</cdoe> for this Login state
     * @return int order of next state. Return
     * @throws AuthLoginException
     */
    private WebauthnRegisterModuleState storeCredentialNameCallback(Callback[] callbacks) throws AuthLoginException {
        
        String credentialname = ((NameCallback) callbacks[1]).getName();
        
        if (StringUtils.isNotEmpty(credentialname)) {
            
            attestedAuthenticator.setCredentialName(credentialname);
            try {
                // boolean _storeResult
                boolean _storeResult = false;
                _storeResult = webauthnService.storeCredentialName(attestedAuthenticator);

                if (_storeResult) {
                    if (DEBUG.messageEnabled()) {
                        DEBUG.message("storeCredentialName was success");
                    }
                    return WebauthnRegisterModuleState.COMPLETE;

                } else {
                    if (DEBUG.messageEnabled()) {
                        DEBUG.message("storeCredentialName was Fail");
                    }
                    return WebauthnRegisterModuleState.REG_START;

                }
            } catch (Exception e) {
                DEBUG.error("Webauthn.storeCredentialName : Webauthn module exception : ", e);
                return WebauthnRegisterModuleState.REG_START;
            }

        } else {
            return WebauthnRegisterModuleState.COMPLETE;
        }
        
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
