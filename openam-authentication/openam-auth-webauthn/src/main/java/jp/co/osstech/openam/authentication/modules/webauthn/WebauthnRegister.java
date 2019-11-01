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
import javax.security.auth.callback.TextOutputCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.spi.MessageLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchOpModifier;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Iterator;
//import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.Base64;
import java.lang.Byte;
import java.lang.reflect.Field;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.type.MapType;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.security.auth.login.LoginException;

import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.devices.services.AuthenticatorDeviceServiceFactory;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.utils.qr.ErrorCorrectionLevel;
import org.forgerock.util.encode.Base64url;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.PublicKeyCredential;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.exception.*;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnService;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnServiceFactory;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.*;

public class WebauthnRegister extends AMLoginModule {

    private static final String BUNDLE_NAME = "amAuthWebauthnRegister";
    private final static Debug DEBUG = Debug.getInstance(WebauthnRegister.class.getSimpleName());

    private ResourceBundle bundle;
    private Map sharedState;
    private Map options;

    // user's valid ID and principal
    private String validatedUserID;
    private WebauthnPrincipal userPrincipal;

    // Webauthn Credentials
    private String userName;
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

    // Service Configuration Parameters
    private String rpNameConfig = "";
    private String originConfig = "";
    private String attestationConfig = "";
    private String attachmentConfig = "";
    private String residentKeyConfig = "";
    private String userVerificationConfig = "";
    private String timeoutConfig = "";
    private String credentialIdAttributeNameConfig = "";
    private String pubKeyAttributeNameConfig = "";
    private String displayNameAttributeNameConfig = "";
    private String counterAttributeNameConfig = "";

    // Service Configuration Strings
    private static final String RP_NAME = "iplanet-am-auth-Webauthn-rp";
    private static final String ORIGIN = "iplanet-am-auth-Webauthn-origin";
    private static final String ATTESTATION = "iplanet-am-auth-Webauthn-attestation";
    private static final String ATTACHMENT = "iplanet-am-auth-Webauthn-attachment";
    private static final String RESIDENTKEY = "iplanet-am-auth-Webauthn-residentKey";
    private static final String USER_VERIFICATION = "iplanet-am-auth-Webauthn-userVerification";
    private static final String TIMEOUT = "iplanet-am-auth-Webauthn-timeout";
    private static final String CREDENTIALID_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-credentialIdAttributeName";
    private static final String PUBLIC_KEY_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-keyAttributeName";
    private static final String DISPLAY_NAME_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-displayNameAttributeName";
    private static final String COUNTER_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-counterAttributeName";
    private static final String AUTH_LEVEL = "iplanet-am-auth-Webauthn-auth-level";

    // Default Values.
    private static final int DEFAULT_AUTH_LEVEL = 0;

    private Set<String> userSearchAttributes = Collections.emptySet();
    private Callback[] callbacks;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
    private final AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService> webauthnServiceFactory =
            InjectorHolder.getInstance(Key.get(
                    new TypeLiteral<AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService>>(){},
                    Names.named(AuthenticatorWebAuthnServiceFactory.FACTORY_NAME)));
    private AuthenticatorWebAuthnService webauthnService;
    
    /**
     * Initializes this <code>LoginModule</code>.
     *
     * @param subject     the <code>Subject</code> to be authenticated.
     * @param sharedState shared <code>LoginModule</code> state.
     * @param options     options specified in the login. <code>Configuration</code>
     *                    for this particular <code>LoginModule</code>.
     */
    public void init(Subject subject, Map sharedState, Map options) {

        java.util.Locale locale = getLoginLocale();
        bundle = amCache.getResBundle(BUNDLE_NAME, locale);

        this.rpNameConfig = CollectionHelper.getMapAttr(options, RP_NAME);
        this.originConfig = CollectionHelper.getMapAttr(options, ORIGIN);
        this.attestationConfig = CollectionHelper.getMapAttr(options, ATTESTATION);
        this.attachmentConfig = CollectionHelper.getMapAttr(options, ATTACHMENT);
        this.residentKeyConfig = CollectionHelper.getMapAttr(options, RESIDENTKEY);
        this.userVerificationConfig = CollectionHelper.getMapAttr(options, USER_VERIFICATION);
        this.timeoutConfig = CollectionHelper.getMapAttr(options, TIMEOUT);
        this.credentialIdAttributeNameConfig = CollectionHelper.getMapAttr(options, CREDENTIALID_ATTRIBUTE_NAME);
        this.pubKeyAttributeNameConfig = CollectionHelper.getMapAttr(options, PUBLIC_KEY_ATTRIBUTE_NAME);
        this.displayNameAttributeNameConfig = CollectionHelper.getMapAttr(options, DISPLAY_NAME_ATTRIBUTE_NAME);
        this.counterAttributeNameConfig = CollectionHelper.getMapAttr(options, COUNTER_ATTRIBUTE_NAME);


        if (DEBUG.messageEnabled()) {
            DEBUG.message("Webauthn module parameter are " 
                    + ", rpName = " + rpNameConfig
                    + ", origin = " + originConfig 
                    + ", attestation = " + attestationConfig
                    + ", attachment = " + attachmentConfig 
                    + ", residentKey = " + residentKeyConfig
                    + ", userVerification = " + userVerificationConfig 
                    + ", timeoutConfig = " + timeoutConfig
                    + ", credentialIdAttributeName = " + credentialIdAttributeNameConfig
                    + ", displayNameAttributeName = " + displayNameAttributeNameConfig 
                    + ", keyAttributeName = " + pubKeyAttributeNameConfig 
                    + ", counterAttributeName = " + counterAttributeNameConfig);
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

    /**
     * Takes an array of submitted <code>Callback</code>, process them and decide
     * the order of next state to go. Return STATE_SUCCEED if the login is
     * successful, return STATE_FAILED if the LoginModule should be ignored.
     *
     * @param callbacks an array of <code>Callback</cdoe> for this Login state
     * @param state     order of state. State order starts with 1.
     * @return int order of next state. Return STATE_SUCCEED if authentication is
     *         successful, return STATE_FAILED if the LoginModule should be ignored.
     * @throws AuthLoginException
     */
    public int process(Callback[] callbacks, int state) throws AuthLoginException {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("in process(), login state is " + state);
        }

        this.callbacks = callbacks;
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
                nextState = WebauthnRegisterModuleState.REG_START;
                break;
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
            // only display next button and return LOGIN_START
            nextState = WebauthnRegisterModuleState.COMPLETE;

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
            
            // store userHandleId as Base64Url String
            /* comment out 20191028
            if (lookupStringData(userHandleIdAttributeNameConfig).isEmpty()) {
            _storeResult = storeStringData(Base64UrlUtil.encodeToString(userHandleIdBytes), userHandleIdAttributeNameConfig);
            }
            */
            // store CredentialId as Base64Url String
            _storeResult = storeStringData(Base64UrlUtil.encodeToString(attestedCredentialIdBytes), credentialIdAttributeNameConfig);

            // store Public Key as COSE Key Binary
            CborConverter _cborConverter = new CborConverter();
            _storeResult = storeByteData(
                    _cborConverter.writeValueAsBytes(attestedCredentialPublicKey),
                    pubKeyAttributeNameConfig);

            // store Counter as String
            _storeResult = storeStringData(String.valueOf(attestedCounter), counterAttributeNameConfig);

            String realm = DNMapper.orgNameToRealmName(getRequestOrg());
            webauthnService = webauthnServiceFactory.create(realm);
            WebAuthnAuthenticator authenticator = new WebAuthnAuthenticator(
                    Base64UrlUtil.encodeToString(attestedCredentialIdBytes),
                    _cborConverter.writeValueAsBytes(attestedCredentialPublicKey),
                    new Long(attestedCounter), userHandleIdBytes);
            webauthnService.createAuthenticator(authenticator);
            
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
     * Store StringData to user data store
     * @param String attestedStringData,
     * @param String attributeName
     * @return boolean
     * @throws AuthLoginException IdRepoException
     */
    private boolean storeStringData(String attestedStringData, String attributeName)
            throws AuthLoginException, IdRepoException {
        boolean _storeStringDataResult = false;
        Map<String, Set> _map = new HashMap<String, Set>();
        Set<String> _values = new HashSet<String>();
        //String _storeString = String.valueOf(attestedStringData);
        //_values.add(_storeString);
        _values.add(attestedStringData);
        _map.put(attributeName, _values);

        try {
            AMIdentity uid = getIdentity();
            uid.setAttributes(_map);
            uid.store();
            _storeStringDataResult = true;
        } catch (SSOException e) {
            DEBUG.error("Webauthn.storeStringData() : Webauthn module exception : ", attributeName, e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        } catch (IdRepoException ex) {
            DEBUG.error("Webauthn.storeStringData() : error store String : ", attributeName, ex);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message("storeStringData was Success", attributeName);
        }
        return _storeStringDataResult;
    }

    /*
     * Store ByteData to user data store
     * @param byte[] attestedByteData,
     * @param String attributeName
     * @return boolean
     * @throws AuthLoginException, IdRepoException
     */
    private boolean storeByteData(byte[] attestedByteData, String attributeName)
            throws AuthLoginException, IdRepoException {

        boolean _storeByteDataResult = false;

        byte[] _attestedData = attestedByteData;
        Map<String, byte[][]> map = new HashMap<String, byte[][]>();
        byte[][] _attestedValues = new byte[1][];
        map.put(attributeName, _attestedValues);
        _attestedValues[0] = _attestedData;

        try {
            AMIdentity uid = getIdentity();
            uid.setBinaryAttributes(map);
            uid.store();
            _storeByteDataResult = true;
        } catch (SSOException e) {
            DEBUG.error("Webauthn.storeByteData : Webauthn module exception : ", attributeName, e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        } catch (IdRepoException ex) {
            DEBUG.error("Webauthn.storeByteData : error store StringData : ", attributeName, ex);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message("storeByteData was Success", attributeName);
        }
        return _storeByteDataResult;
    }

    /*
     * lookup StringData user data store
     * @return String
     * @throws AuthLoginException
     */
    private String lookupStringData(String attributeName) throws AuthLoginException {
        Set<String> _attributes = Collections.emptySet();

        try {
            _attributes = getIdentity().getAttribute(attributeName);
        } catch (SSOException e) {
            DEBUG.error("Webauthn.lookupDisplayNames() : Webauthn module exception : ", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        } catch (IdRepoException e) {
            DEBUG.error("Webauthn.lookupDisplayNames() : error searching Identities with username : " + userName, e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        }

        String _attribute = "";

        if (CollectionUtils.isNotEmpty(_attributes)) {
            _attribute = _attributes.iterator().next();
        } 
        return _attribute;
    }
    
    /*
     * lookup Byte user data store
     * @return byte[]
     * @throws AuthLoginException
     */
    private byte[] lookupByteData(String attributeName) throws AuthLoginException {

        Set<String> _attribute = CollectionUtils.asSet(attributeName);

        try {
            Map<String, byte[][]> _lookupByteData = getIdentity().getBinaryAttributes(_attribute);
            return _lookupByteData.get(attributeName)[0];
        } catch (SSOException e) {
            DEBUG.error("Webauthn.lookupCredentialId() : Webauthn module exception : ", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        } catch (IdRepoException e) {
            DEBUG.error("Webauthn.lookupCredentialId() : error searching Identities with username : " + userName, e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        }
    }


    /* generate secure random byte[]
     * @param int length
     * @return byte[]
     */
    private byte[] genSecureRandomBytesArray(int arrayLength) throws GeneralSecurityException {
        SecureRandom _randam = new SecureRandom();
        byte[] _byteArray = new byte[arrayLength];
        _randam.nextBytes(_byteArray);

        return _byteArray;
    }

    /**
     * from based membership
     * module==============================================================================================
     * User input value will be store in the callbacks[]. When user click cancel
     * button, these input field should be reset to blank.
     */
    private void clearCallbacks(Callback[] callbacks) {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof NameCallback) {
                NameCallback nc = (NameCallback) callbacks[i];
                nc.setName("");
            }
        }
    }

    /**
     * from based membership module Returns <code>Principal</code>.
     *
     * @return <code>Principal</code>
     */
    public Principal getPrincipal() {
        if (userPrincipal != null) {
            return userPrincipal;
        } else if (validatedUserID != null) {
            userPrincipal = new WebauthnPrincipal(validatedUserID);
            return userPrincipal;
        } else {
            return null;
        }
    }

    /**
     * from based membership module Destroy the module state
     */
    @Override
    public void destroyModuleState() {
        validatedUserID = null;
    }

    /**
     * from based membership module Set all the used variables to null
     */
    @Override
    public void nullifyUsedVars() {
        bundle = null;
        sharedState = null;
        options = null;
        userName = null;
        //        userAttrs = null;
        callbacks = null;
    }

    /*
     * from based membership module
     * 
     */
    private AMIdentity getIdentity() throws SSOException, IdRepoException {
        AMIdentity _theID = null;
        AMIdentityRepository _amIdRepo = getAMIdentityRepository(getRequestOrg());

        IdSearchControl _idsc = new IdSearchControl();
        _idsc.setAllReturnAttributes(true);
        Set<AMIdentity> _results = Collections.emptySet();

        try {
            IdSearchResults _searchResults = _amIdRepo.searchIdentities(IdType.USER, userName, _idsc);
            if (_searchResults.getSearchResults().isEmpty() && !userSearchAttributes.isEmpty()) {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("{}.getIdentity : searching user identity with alternative attributes {}", "Webauthn",
                            userSearchAttributes);
                }
                Map<String, Set<String>> searchAVP = CollectionUtils.toAvPairMap(userSearchAttributes, userName);
                _idsc.setSearchModifiers(IdSearchOpModifier.OR, searchAVP);
                _searchResults = _amIdRepo.searchIdentities(IdType.USER, "*", _idsc);
            }

            if (_searchResults != null) {
                _results = _searchResults.getSearchResults();
            }
        } catch (SSOException e) {
            DEBUG.error("{}.getIdentity : Error searching Identities with username '{}' ", "Webauthn", userName, e);
        } catch (IdRepoException e) {
            DEBUG.error("{}.getIdentity : Module exception", "Webauthn", e);
        }

        if (_results.isEmpty()) {
            DEBUG.error("{}.getIdentity : User '{}' is not found", "Webauthn", userName);
        } else if (_results.size() > 1) {
            DEBUG.error("{}.getIdentity : More than one user found for the userName '{}'", "Webauthn", userName);
        } else {
            _theID = _results.iterator().next();
        }

        return _theID;
    }
}
