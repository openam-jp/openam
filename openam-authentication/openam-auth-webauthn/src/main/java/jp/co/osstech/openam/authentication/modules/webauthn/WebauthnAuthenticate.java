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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.UUID;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.lang.Byte;
import java.nio.ByteBuffer;

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
import javax.xml.bind.DatatypeConverter;

import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.utils.qr.ErrorCorrectionLevel;
import org.forgerock.util.encode.Base64url;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.UUIDUtil;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;

public class WebauthnAuthenticate extends AMLoginModule {

    private static final String BUNDLE_NAME = "amAuthWebauthnAuthenticate";
    private final static Debug DEBUG = Debug.getInstance(WebauthnAuthenticate.class.getSimpleName());

    private ResourceBundle bundle;
    private Map sharedState;
    private Map options;
    private int authLevel;
    private String getType;
    private String getUserHandle;

    // user's valid ID and principal
    private String validatedUserID;
    private WebauthnPrincipal userPrincipal;

    // Webauthn Credentials
    private String userName;
    private byte[] credentialIdBytes;
    private CredentialPublicKey credentialPublicKey;
    private byte[] rawIdBytes;
    private String webauthnHiddenCallback;
    private Challenge generatedChallenge;
    private byte[] challengeBytes;
    private boolean updateCounterResult = false;
    private boolean verificationRequired;
    private byte[] authenticatorDataBytes;
    private byte[] signatureBytes;
    private byte[] clientDataJsonBytes;

    // Service Configuration Parameters
    private String useMfaConfig = "";
    private String rpNameConfig = "";
    private String originConfig = "";
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
    private static final String RESIDENTKEY = "iplanet-am-auth-Webauthn-residentKey";
    private static final String USER_VERIFICATION = "iplanet-am-auth-Webauthn-userVerification";
    private static final String TIMEOUT = "iplanet-am-auth-Webauthn-timeout";
    private static final String CREDENTIALID_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-credentialIdAttributeName";
    private static final String PUBLIC_KEY_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-keyAttributeName";
    private static final String DISPLAY_NAME_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-displayNameAttributeName";
    private static final String COUNTER_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-counterAttributeName";
    private static final String AUTH_LEVEL = "iplanet-am-auth-Webauthn-auth-level";
    private static final String USE_MFA = "iplanet-am-auth-Webauthn-useMfa";

    // Default Values.
    private static final int DEFAULT_AUTH_LEVEL = 0;

    private boolean getCredentialsFromSharedState;
    private Callback[] callbacks;
    private Set<String> userSearchAttributes = Collections.emptySet();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Initializes this <code>LoginModule</code>.
     *
     * @param subject     the <code>Subject</code> to be authenticated.
     * @param sharedState shared <code>LoginModule</code> state.
     * @param options     options specified in the login. <code>Configuration</code>
     *                    for this particular <code>LoginModule</code>.
     */
    public void init(Subject subject, Map sharedState, Map options) {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("Webauthn module init start");
        }
        java.util.Locale locale = getLoginLocale();
        bundle = amCache.getResBundle(BUNDLE_NAME, locale);

        if (DEBUG.messageEnabled()) {
            DEBUG.message("Webauthn getting resource bundle for locale: " + locale);
        }

        this.authLevel = CollectionHelper.getIntMapAttr(options, AUTH_LEVEL, DEFAULT_AUTH_LEVEL, DEBUG);
        this.useMfaConfig = CollectionHelper.getMapAttr(options, USE_MFA);
        this.rpNameConfig = CollectionHelper.getMapAttr(options, RP_NAME);
        this.originConfig = CollectionHelper.getMapAttr(options, ORIGIN);
        this.residentKeyConfig = CollectionHelper.getMapAttr(options, RESIDENTKEY);
        this.userVerificationConfig = CollectionHelper.getMapAttr(options, USER_VERIFICATION);
        this.timeoutConfig = CollectionHelper.getMapAttr(options, TIMEOUT);
        this.credentialIdAttributeNameConfig = CollectionHelper.getMapAttr(options, CREDENTIALID_ATTRIBUTE_NAME);
        this.pubKeyAttributeNameConfig = CollectionHelper.getMapAttr(options, PUBLIC_KEY_ATTRIBUTE_NAME);
        this.displayNameAttributeNameConfig = CollectionHelper.getMapAttr(options, DISPLAY_NAME_ATTRIBUTE_NAME);
        this.counterAttributeNameConfig = CollectionHelper.getMapAttr(options, COUNTER_ATTRIBUTE_NAME);

        if (DEBUG.messageEnabled()) {
            DEBUG.message("Webauthn module parameter are " 
                    + "authLevel = " + authLevel
                    + ", useMfa = " + useMfaConfig 
                    + ", rpName = " + rpNameConfig
                    + ", origin = " + originConfig 
                    + ", residentKey = " + residentKeyConfig
                    + ", userVerification = " + userVerificationConfig 
                    + ", timeoutConfig = " + timeoutConfig
                    + ", credentialIdAttributeName = " + credentialIdAttributeNameConfig
                    + ", displayNameAttributeName = " + displayNameAttributeNameConfig 
                    + ", keyAttributeName = " + pubKeyAttributeNameConfig 
                    + ", counterAttributeName = " + counterAttributeNameConfig);
        }
        if(useMfaConfig.equalsIgnoreCase("true")) {
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
        WebauthnAuthenticateModuleState moduleState = WebauthnAuthenticateModuleState.get(state);
        WebauthnAuthenticateModuleState nextState = null;

        switch (moduleState) {
        
        case LOGIN_SELECT:
            if (useMfaConfig.equalsIgnoreCase("true")) {
                nextState = WebauthnAuthenticateModuleState.MFA_LOGIN_START;
            } else if (residentKeyConfig.equalsIgnoreCase("true")) {
                nextState = WebauthnAuthenticateModuleState.RESIDENTKEY_LOGIN_START;
            } else {
                nextState = WebauthnAuthenticateModuleState.LOGIN_START;
            }
            break;
        

        case LOGIN_START:

            if (DEBUG.messageEnabled()) {
                DEBUG.message("ThisState = WebauthnAuthenticateModuleStat.LOGIN_START");
            }

            // Authentication Start
            // expect LOGIN_SCRIPT
            try {
                nextState = getStoredCredentialId(callbacks);
            } catch (AuthLoginException ex) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
            }

            // generate 16byte challenge
                generatedChallenge = new DefaultChallenge();
                challengeBytes = ArrayUtil.clone(generatedChallenge.getValue());

            // navigator.credentials.get Options
            CredentialsGetOptions credentialsGetOptions = new CredentialsGetOptions(
                    credentialIdBytes,
                    userVerificationConfig,
                    challengeBytes,
                    timeoutConfig,
                    residentKeyConfig);

            // Replace Callback to send Generated Javascript that include get options.
            // only for nextState LOGIN_SCRIPT
            Callback creadentialsGetCallback = new ScriptTextOutputCallback(
                    credentialsGetOptions.generateCredntialsGetScriptCallback());
            replaceCallback(WebauthnAuthenticateModuleState.LOGIN_SCRIPT.intValue(), 0, creadentialsGetCallback);

            break;

        case LOGIN_SCRIPT:

            if (DEBUG.messageEnabled()) {
                DEBUG.message("ThisState = WebauthnAuthenticateModuleStat.LOGIN_SCRIPT");
            }

            // Verify User Credential for Webauthn authentication
            try {
                nextState = verifyAuthenticatorCallback(callbacks);
            } catch (Exception ex) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
            }

            break;
 
        case RESIDENTKEY_LOGIN_START:

            if (DEBUG.messageEnabled()) {
                DEBUG.message("ThisState = WebauthnAuthenticateModuleStat.RESIDENTKEY_LOGIN_START");
            }

            nextState = WebauthnAuthenticateModuleState.LOGIN_SCRIPT;
                    
            // generate 16byte challenge
            generatedChallenge = new DefaultChallenge();
            challengeBytes = ArrayUtil.clone(generatedChallenge.getValue());

            // navigator.credentials.get Options
            //redidentkey dosn't need stored credentialid.
            byte[] idBytes = new byte[0];
            CredentialsGetOptions residentkeyCredentialsGetOptions = new CredentialsGetOptions(
                    idBytes,
                    userVerificationConfig,
                    challengeBytes,
                    timeoutConfig,
                    residentKeyConfig);

            // Replace Callback to send Generated Javascript that include get options.
            // only for nextState LOGIN_SCRIPT
            Callback residentkeyCreadentialsGetCallback = new ScriptTextOutputCallback(
                    residentkeyCredentialsGetOptions.generateCredntialsGetScriptCallback());
            replaceCallback(WebauthnAuthenticateModuleState.LOGIN_SCRIPT.intValue(), 0, residentkeyCreadentialsGetCallback);

            break;
            
        case MFA_LOGIN_START:

            if (DEBUG.messageEnabled()) {
                DEBUG.message("ThisState = WebauthnAuthenticateModuleStat.MFA_LOGIN_START");
            }

            // Authentication Start
            // expect LOGIN_SCRIPT
            try {
                nextState = getMfaStoredCredentialId();
            } catch (AuthLoginException ex) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
            }

            // generate 16byte challenge
            generatedChallenge = new DefaultChallenge();
            challengeBytes = ArrayUtil.clone(generatedChallenge.getValue());

            // navigator.credentials.get Options

            CredentialsGetOptions mfaCredentialsGetOptions = new CredentialsGetOptions(
                    credentialIdBytes,
                    userVerificationConfig,
                    challengeBytes,
                    timeoutConfig,
                    residentKeyConfig);

            // Replace Callback to send Generated Javascript that include get options.
            // only for nextState LOGIN_SCRIPT
            Callback mfaCreadentialsGetCallback = new ScriptTextOutputCallback(
                    mfaCredentialsGetOptions.generateCredntialsGetScriptCallback());
            replaceCallback(WebauthnAuthenticateModuleState.LOGIN_SCRIPT.intValue(), 0, mfaCreadentialsGetCallback);

            break;

        }

        return nextState.intValue();
    }

    /*
     * Webauthn Authentication LOGIN_START lookup user webauthn data from datastore
     * #TODO PublicKey from lookupCredentialId()
     * 
     * @param callbacks an array of <code>Callback</cdoe> for this Login state
     * 
     * @return int order of next state.
     * 
     * @throws AuthLoginException
     */
    private WebauthnAuthenticateModuleState getStoredCredentialId(Callback[] callbacks) throws AuthLoginException {
        Callback[] idCallbacks = new Callback[1];

        if (callbacks != null && callbacks.length == 0) {
            userName = (String) sharedState.get(getUserKey());

            if (userName == null) {
                return WebauthnAuthenticateModuleState.LOGIN_START;
            }

            getCredentialsFromSharedState = true;
            NameCallback nameCallback = new NameCallback("dummy");
            nameCallback.setName(userName);
            idCallbacks[0] = nameCallback;

        } else {
            idCallbacks = callbacks;
            // callbacks is not null
            userName = ((NameCallback) callbacks[0]).getName();
        }

        /*
         * lookup CredentialId(Base64Url encoded) from User Data store
         */
        try {
            credentialIdBytes = Base64UrlUtil.decode(lookupStringData(credentialIdAttributeNameConfig));

            if (credentialIdBytes != null) {
                validatedUserID = userName;
                DEBUG.message("validateUserID is " + userName);

                return WebauthnAuthenticateModuleState.LOGIN_SCRIPT;
                // return WebauthnModuleState.COMPLETE;
            } else {
                DEBUG.message("CredentialId is null ");
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
        } catch (AuthLoginException ex) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
        }
    }
    
    private WebauthnAuthenticateModuleState getMfaStoredCredentialId() throws AuthLoginException {

 
        if (userName == null) {
            return WebauthnAuthenticateModuleState.LOGIN_START; //Must be FAIL #TODO
        }
        /*
         * lookup CredentialId(Base64Url encoded) from User Data store
         */
        try {
            credentialIdBytes = Base64UrlUtil.decode(lookupStringData(credentialIdAttributeNameConfig));

            if (credentialIdBytes != null) {
                validatedUserID = userName;
                DEBUG.message("validateUserID is " + userName);

                return WebauthnAuthenticateModuleState.LOGIN_SCRIPT;
                // return WebauthnModuleState.COMPLETE;
            } else {
                DEBUG.message("CredentialId is null ");
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
        } catch (AuthLoginException ex) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
        }
    }

    /*
     * Verify Authenticator(browser) Response Credentials for Authentication #TODO
     * Verify function is not completed.
     * 
     * @param callbacks an array of <code>Callback</cdoe> for this Login state
     * 
     * @return int order of next state. Return STATE_SUCCEED if authentication is
     * successful
     * 
     * @throws AuthLoginException
     */
    private WebauthnAuthenticateModuleState verifyAuthenticatorCallback(Callback[] callbacks)
            throws AuthLoginException, ClassNotFoundException, IOException {

        // read HiddenValueCallback from Authenticator posted
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof HiddenValueCallback) {
                webauthnHiddenCallback = ((HiddenValueCallback) callbacks[i]).getValue();

                if (webauthnHiddenCallback == null) {
                    return WebauthnAuthenticateModuleState.LOGIN_START;
                }
            }
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message("Posted webauthnHiddenCallback = " + webauthnHiddenCallback);
        }

        /*
         * Map Callback Json to Object
         */
        if (StringUtils.isNotEmpty(webauthnHiddenCallback)) {

            try {
                WebauthnJsonCallback _responseJson = OBJECT_MAPPER.readValue(webauthnHiddenCallback,
                        WebauthnJsonCallback.class);

                if (DEBUG.messageEnabled()) {
                    DEBUG.message("id Base64Url = " + _responseJson.getId());
                }

                rawIdBytes = Base64.getDecoder().decode(_responseJson.getRawId());

                authenticatorDataBytes = Base64.getDecoder().decode(_responseJson.getAuthenticatorData());

                clientDataJsonBytes = Base64.getDecoder().decode(_responseJson.getClientDataJSON());

                signatureBytes = Base64.getDecoder().decode(_responseJson.getSignature());

                getType = _responseJson.getType();

                getUserHandle = _responseJson.getUserHandle();
                
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("_responseJson.getUserHandle() = " + _responseJson.getUserHandle());
                }

            } catch (IOException e) {
                DEBUG.error("Webauthn.process(): JSON parse error", e);
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
            }
        }

        /*
         * if residentKey = true
         * get UserHandle in Client Response
         * and using this base64encoded binary as entryUUID
         * to search userName from datastore
         */
        if (residentKeyConfig.equalsIgnoreCase("true")) {
            String _userHandleIdStr = byteArrayToAsciiString(Base64Util.decode(getUserHandle));
            userName = searchUserNameWithAttrValue(_userHandleIdStr,"entryUUID");
            
            /*
             * lookup CredentialId(Base64Url encoded) from User Data store
             */
            try {
                credentialIdBytes = Base64UrlUtil.decode(lookupStringData(credentialIdAttributeNameConfig));

                if (credentialIdBytes != null) {
                    validatedUserID = userName;
                    DEBUG.message("validateUserID is " + userName);

                    // return WebauthnModuleState.COMPLETE;
                } else {
                    DEBUG.message("CredentialId is null ");
                    throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
                }
            } catch (AuthLoginException ex) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
            }
        }
        
        /*
         * Validation authenticator response This must be change to W3C verification
         * flow. Use webauthn4j library to END 
         * START============================.
         */
        Origin _origin = new Origin(originConfig);
        String _rpId = _origin.getHost();
        byte[] _tokenBindingId = null; /* now set tokenBindingId null */
        ServerProperty serverProperty = new ServerProperty(_origin, _rpId, generatedChallenge, _tokenBindingId);

        if (userVerificationConfig.equalsIgnoreCase("required")) {
            verificationRequired = true;
        } else {
            verificationRequired = false;
        }

        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(rawIdBytes,
                clientDataJsonBytes, authenticatorDataBytes, signatureBytes, serverProperty,
                verificationRequired);


        //load Construct Authenticator Object from datastore values.
        Authenticator authenticator = loadAuthenticator(); 

        WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator = new WebAuthnAuthenticationContextValidator();

        WebAuthnAuthenticationContextValidationResponse response = webAuthnAuthenticationContextValidator
                .validate(authenticationContext, authenticator);

        try {
            //update datastore counter value for next authentication.
            updateCounterResult = storeStringData(String.valueOf(response.getAuthenticatorData().getSignCount()), counterAttributeNameConfig);
        } catch (Exception e) {
            DEBUG.error("updateCounter error");
        }
        /*
         * END of webauthn4j library line 
         * END============================
         */

        if (updateCounterResult) {
            setAuthLevel(authLevel);
            if (DEBUG.messageEnabled()) {
                DEBUG.message("Webauthn Authentication success");
            }

            return WebauthnAuthenticateModuleState.COMPLETE;

        } else {
            if (DEBUG.messageEnabled()) {
                DEBUG.message("Webauthn Authentication Fail");
            }
            return WebauthnAuthenticateModuleState.LOGIN_START;

        }
    }
    /**
    * Searches for an account with userHandle userID in the organization organization
    * @param attributeValue The attributeValue to compare when searching for an
    *  identity
    * @param attributeName that name of where the identity will be
    *  looked up
    * @return the UserName
     * @throws AuthLoginException 
    */
    private String searchUserNameWithAttrValue(String attributeValue, String attributeName) throws AuthLoginException {
 
        if (DEBUG.messageEnabled()) {
            DEBUG.message("serchUserNameWith attributeName= "+ attributeName 
                    + " attributeValue= " + attributeValue );
        }

        // And the search criteria
        IdSearchControl _searchControl = new IdSearchControl();
        _searchControl.setMaxResults(1);
        _searchControl.setTimeOut(3000);
        Set<String> _attrName = new HashSet<String>();
        _attrName.add(attributeName);
        final Map<String, Set<String>> _searchAVMap = CollectionUtils.toAvPairMap(_attrName, attributeValue);
        _searchControl.setSearchModifiers(IdSearchOpModifier.OR, _searchAVMap);
        _searchControl.setAllReturnAttributes(false);

        try {
            AMIdentityRepository _amirepo = getAMIdentityRepository(getRequestOrg());

            IdSearchResults _searchResults = _amirepo.searchIdentities(IdType.USER, "*", _searchControl);
            if (_searchResults.getErrorCode() == IdSearchResults.SUCCESS && _searchResults != null) {
                Set<AMIdentity> _results = _searchResults.getSearchResults();
                if (!_results.isEmpty()) {
                    if (DEBUG.messageEnabled()) {
                        DEBUG.message(BUNDLE_NAME + _results.size() + " result(s) obtained");
                    }
                    AMIdentity _userDNId = _results.iterator().next();
                    if (_userDNId != null) {
                        if (DEBUG.messageEnabled()) {
                             DEBUG.message(BUNDLE_NAME + "user = " + _userDNId.getUniversalId());
                             DEBUG.message(BUNDLE_NAME + "attrs =" + _userDNId.getAttributes(
                                     getUserAliasList()));
                        }
                        return _userDNId.getName();
                    }
                }
            }
        } catch (IdRepoException idrepoex) {

            throw new AuthLoginException(BUNDLE_NAME, idrepoex);
        } catch (SSOException ssoe) {

            throw new AuthLoginException(BUNDLE_NAME, ssoe);
        }
        if (DEBUG.messageEnabled()) {
                    DEBUG.message(BUNDLE_NAME + " No results were found !");
        }
        return null;
    }

    /*
     * load Authenticator Object data for use webauthn4j validation
     */
    private Authenticator loadAuthenticator() throws AuthLoginException, IOException, ClassNotFoundException {

        // OpenAM didn't store aaguid now. Use ZERO AAGUID.
        AAGUID _aaguid = AAGUID.ZERO;

        //credentialPublicKey was stored as COSEKey byte[] data at registration time.
        CborConverter _cborConverter = new CborConverter();
        credentialPublicKey = _cborConverter.readValue(lookupByteData(pubKeyAttributeNameConfig), CredentialPublicKey.class);

        final AttestedCredentialData storedAttestedCredentialData = new AttestedCredentialData(_aaguid,
                credentialIdBytes, credentialPublicKey);
        final AttestationStatement noneAttestationStatement = new NoneAttestationStatement();
        final long storedCounter = Long.parseLong(lookupStringData(counterAttributeNameConfig));
        Authenticator storedAuthenticator = new AuthenticatorImpl(storedAttestedCredentialData,
                noneAttestationStatement, storedCounter);

        return storedAuthenticator;
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

        String _attribute = null;

        if (org.apache.commons.collections.CollectionUtils.isNotEmpty(_attributes)) {
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

    /*
     * Convert Byte Array user.id(userHandle=entryUUID)
     * to
     * ASCII String for search entryUUID
     */
    private String byteArrayToAsciiString(byte[] bytes) {
        StringBuffer _sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            _sb.append( Character.toChars(bytes[i]) );
        }
        return _sb.toString();
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
     * from based membership module Returns the password from the PasswordCallback.
     */
    private String getPassword(PasswordCallback callback) {
        char[] tmpPassword = callback.getPassword();

        if (tmpPassword == null) {
            // treat a NULL password as an empty password
            tmpPassword = new char[0];
        }

        char[] pwd = new char[tmpPassword.length];
        System.arraycopy(tmpPassword, 0, pwd, 0, tmpPassword.length);

        return (new String(pwd));
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
        // userAttrs = null;
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
