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
import com.sun.identity.sm.SMSException;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchOpModifier;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Base64;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.devices.services.AuthenticatorDeviceServiceFactory;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.encode.Base64url;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
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
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnService;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnServiceFactory;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

public class WebauthnAuthenticate extends AbstractWebAuthnModule {

    private static final String BUNDLE_NAME = "amAuthWebauthnAuthenticate";
    private final static Debug DEBUG = Debug.getInstance(WebauthnAuthenticate.class.getSimpleName());
    
    // Configuration Strings for Authenticate
    private static final String USE_MFA = "iplanet-am-auth-Webauthn-useMfa";

    // Configuration Parameters for Authenticate
    private String useMfaConfig = "";
    
    private String getType;
    private String getUserHandle;

    // user's valid ID and principal
    private String validatedUserID;
    private WebauthnPrincipal userPrincipal;

    // Webauthn Credentials
    //private byte[] credentialIdBytes;
    private Set<WebAuthnAuthenticator> authenticators;
    private WebAuthnAuthenticator selectedAuthenticator = null;
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

    private boolean getCredentialsFromSharedState;
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
        
        this.useMfaConfig = CollectionHelper.getMapAttr(options, USE_MFA);

        if (DEBUG.messageEnabled()) {
            DEBUG.message("Webauthn module parameter are " 
                    + "authLevel = " + authLevel
                    + ", useMfa = " + useMfaConfig 
                    + ", rpName = " + rpNameConfig
                    + ", origin = " + originConfig 
                    + ", residentKey = " + residentKeyConfig
                    + ", userVerification = " + userVerificationConfig 
                    + ", timeoutConfig = " + timeoutConfig
                    + ", displayNameAttributeName = " + displayNameAttributeNameConfig);
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
    
    @Override
    public int process(Callback[] callbacks, int state) throws AuthLoginException {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("in process(), login state is " + state);
        }

        WebauthnAuthenticateModuleState moduleState = WebauthnAuthenticateModuleState.get(state);
        WebauthnAuthenticateModuleState nextState = null;

        switch (moduleState) {
        
        case LOGIN_SELECT:
            try {
                String realm = DNMapper.orgNameToRealmName(getRequestOrg());
                webauthnService = webauthnServiceFactory.create(realm);
            } catch (SSOException|SMSException ex) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
            }
            
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
                    authenticators,
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
            CredentialsGetOptions residentkeyCredentialsGetOptions = 
                    new CredentialsGetOptions(
                    null,
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
                    authenticators,
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
            byte[] entryUUID = lookupByteData("entryUUID");
            authenticators = webauthnService.getAuthenticators(entryUUID);
            if (authenticators.isEmpty()) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
            return WebauthnAuthenticateModuleState.LOGIN_SCRIPT;
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
            byte[] entryUUID = lookupByteData("entryUUID");
            authenticators = webauthnService.getAuthenticators(entryUUID);
            if (authenticators.isEmpty()) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
            return WebauthnAuthenticateModuleState.LOGIN_SCRIPT;
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
            userName = searchUserNameWithAttrValue(_userHandleIdStr, "entryUUID");
            
            /*
             * lookup CredentialId(Base64Url encoded) from User Data store
             */
            authenticators = webauthnService.getAuthenticators(Base64Util.decode(getUserHandle));
            if (authenticators.isEmpty()) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
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
            selectedAuthenticator.setSignCount(response.getAuthenticatorData().getSignCount());
            updateCounterResult = webauthnService.updateCounter(selectedAuthenticator);
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
            validatedUserID = userName;
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

        for (WebAuthnAuthenticator authenticator : authenticators) {
            if (authenticator.isSelected(Base64url.encode(rawIdBytes))) {
                selectedAuthenticator = authenticator;
                break;
            }
        }
        if (selectedAuthenticator == null) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
        
        //credentialPublicKey was stored as COSEKey byte[] data at registration time.
        CborConverter _cborConverter = new CborConverter();
        credentialPublicKey = _cborConverter.readValue(selectedAuthenticator.getPublicKey(), CredentialPublicKey.class);

        final AttestedCredentialData storedAttestedCredentialData = 
                new AttestedCredentialData(_aaguid, 
                        Base64UrlUtil.decode(selectedAuthenticator.getCredentialID()), credentialPublicKey);
        final AttestationStatement noneAttestationStatement = new NoneAttestationStatement();
        final long storedCounter = selectedAuthenticator.getSignCount();
        Authenticator storedAuthenticator = new AuthenticatorImpl(storedAttestedCredentialData,
                noneAttestationStatement, storedCounter);

        return storedAuthenticator;
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
