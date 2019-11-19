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

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.MessageLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchOpModifier;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.sm.SMSException;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.encode.Base64url;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

/**
 * WebAuthn (Authenticate) Authentication Module.
 */
public class WebAuthnAuthenticate extends AbstractWebAuthnModule {

    public static final String BUNDLE_NAME = "amAuthWebAuthnAuthenticate";
    private static final Debug DEBUG = Debug.getInstance(WebAuthnAuthenticate.class.getSimpleName());
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
    // Module States
    private final int STATE_COMPLETE = -1;
    private final int STATE_LOGIN_SELECT = 1;
    private final int STATE_LOGIN_START = 2;
    private final int STATE_LOGIN_SCRIPT = 3;
    
    // Configuration Strings for Authenticate
    private static final String USE_MFA = "iplanet-am-auth-Webauthn-useMfa";

    // Configuration Parameters for Authenticate
    private String useMfaConfig = "";

    // WebAuthn
    private Set<WebAuthnAuthenticator> authenticators = null;

    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("WebAuthnAuthenticate module init start");
        }

        super.init(subject, sharedState, options);
        
        this.useMfaConfig = CollectionHelper.getMapAttr(options, USE_MFA);

        if (DEBUG.messageEnabled()) {
            DEBUG.message("WebAuthnAuthenticate module parameter are " 
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
                    DEBUG.message("WebAuthnAuthenticate.init() : Cannot lookup userName from shared State.");
                }
            }
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebAuthnAuthenticate.init() : userName is " + userName);
            }
        }
    }
    
    @Override
    public int process(Callback[] callbacks, int state) throws AuthLoginException {
        if (DEBUG.messageEnabled()) {
            DEBUG.message("WebAuthnAuthenticate.process() : login state is " + state);
        }

        int nextState;

        switch (state) {
        
        case STATE_LOGIN_SELECT:
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebAuthnAuthenticate.process() : This state is LOGIN_SELECT.");
            }
            nextState = selectLoginType();
            break;
        case STATE_LOGIN_START:
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebAuthnAuthenticate.process() : This state is LOGIN_START.");
            }
            nextState = handlePasswordLessLoginStartCallbacks(callbacks);
            break;
        case STATE_LOGIN_SCRIPT:
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebAuthnAuthenticate.process() : This state is LOGIN_SCRIPT.");
            }
            nextState = verifyAuthenticatorCallback(callbacks);
            break;
        default:
            DEBUG.error("WebAuthnAuthenticate.process() : Invalid module state.");
            throw new AuthLoginException(BUNDLE_NAME, "invalidModuleState", null);
        }

        return nextState;
    }

    /**
     * Select login type (PasswordLess / ResidentKey / MFA).
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private int selectLoginType() throws AuthLoginException {
        
        int nextState;
        
        try {
            String realm = DNMapper.orgNameToRealmName(getRequestOrg());
            webauthnService = webauthnServiceFactory.create(realm);
        } catch (SSOException|SMSException ex) {
            DEBUG.error("WebAuthnAuthenticate.selectLoginType() : Authenticator service exception : ", ex);
            throw new AuthLoginException(BUNDLE_NAME, "deviceServiceError", null, ex);
        }
        
        if (useMfaConfig.equalsIgnoreCase("true")) {
            if (userName == null) {
                DEBUG.error("WebAuthnAuthenticate.selectLoginType() :  User name not found");
                throw new AuthLoginException(BUNDLE_NAME, "noUserIdentified", null);
            }
            
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebAuthnAuthenticate.selectLoginType() : MFA Login");
            }
            
            // MFA login starting.
            getStoredCredentialId();
            createLoginScript();
            
            nextState = STATE_LOGIN_SCRIPT;
        } else if (residentKeyConfig.equalsIgnoreCase("true")) {
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebAuthnAuthenticate.selectLoginType() : Resident Key Login");
            }

            // resident key login starting.
            createLoginScript();
            
            nextState = STATE_LOGIN_SCRIPT;
        } else {
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebAuthnAuthenticate.selectLoginType() : Password Less Login");
            }
            
            nextState = STATE_LOGIN_START;
        }
        return nextState;
    }

    /**
     * Handle callbacks of password less login starting.
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private int handlePasswordLessLoginStartCallbacks(Callback[] callbacks) 
            throws AuthLoginException {

        userName = ((NameCallback) callbacks[0]).getName();
        
        getStoredCredentialId();
        
        createLoginScript();

        return STATE_LOGIN_SCRIPT;
    }
    
    /**
     * Get user authenticators.
     * 
     * @throws AuthLoginException
     */
    private void getStoredCredentialId() throws AuthLoginException {
        /*
         * lookup CredentialId(Base64Url encoded) from User Data store
         */
        byte[] entryUUID = lookupByteData("entryUUID");
        authenticators = webauthnService.getAuthenticators(entryUUID);
        if (authenticators.isEmpty()) {
            if (DEBUG.warningEnabled()) {
                DEBUG.warning("WebAuthnAuthenticate.getStoredCredentialId() :  User authenticators not found");
            }
            throw new MessageLoginException(BUNDLE_NAME, "msgNoDevice", null);
        }
    }

    /**
     * Create login javascript (credentials.get).
     * 
     * @throws AuthLoginException
     */
    private void createLoginScript() throws AuthLoginException {

        // Generate challenge
        byte[] _challengeBytes = webauthnValidator.generateChallenge();

        // Replace Callback to send Generated Javascript that include get options.
        // only for nextState LOGIN_SCRIPT
        // redidentkey dosn't need stored credentialid(authenticators = null).
        Callback creadentialsGetCallback = 
                ScriptCallbackGenerator.generateCredntialsGetScriptCallback(
                        authenticators,
                        residentKeyConfig,
                        userVerificationConfig,
                        timeoutConfig,
                        _challengeBytes);
        replaceCallback(STATE_LOGIN_SCRIPT, 0, creadentialsGetCallback);
    }

    /**
     * Verify Authenticator(browser) Response Credentials for Authentication
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private int verifyAuthenticatorCallback(Callback[] callbacks)
            throws AuthLoginException {
        
        // if Cancel Button Return Authentication Fail
        if (((ConfirmationCallback)callbacks[2]).getSelectedIndex() == 1) {
            throw new MessageLoginException(BUNDLE_NAME, "msgAuthCancel", null);
        }
        
        // read HiddenValueCallback from Authenticator posted
        String _webauthnHiddenCallback = ((HiddenValueCallback) callbacks[1]).getValue();
        if (StringUtils.isEmpty(_webauthnHiddenCallback)) {
            DEBUG.error("WebAuthnAuthenticate.verifyAuthenticatorCallback() : webauthnHiddenCallback is empty");
            throw new AuthLoginException(BUNDLE_NAME, "emptyCallback", null);
        }
        
        if (DEBUG.messageEnabled()) {
            DEBUG.message("Posted webauthnHiddenCallback = " + _webauthnHiddenCallback);
        }

        /*
         * Map Callback Json to Object
         */
        WebAuthnJsonCallback _responseJson;
        try {
            _responseJson = OBJECT_MAPPER.readValue(_webauthnHiddenCallback, WebAuthnJsonCallback.class);
            if (DEBUG.messageEnabled()) {
                DEBUG.message("id Base64Url = " + _responseJson.getId());
                DEBUG.message("_responseJson.getUserHandle() = " + _responseJson.getUserHandle());
            }
        } catch (IOException e) {
            DEBUG.error("WebAuthnAuthenticate.process(): JSON parse error", e);
            throw new AuthLoginException(BUNDLE_NAME, "jsonParseError", null, e);
        }

        byte[] _userHandleBytes = Base64url.decode(_responseJson.getUserHandle());
        
        /*
         * if residentKey = true
         * get UserHandle in Client Response
         * and using this base64encoded binary as entryUUID
         * to search userName from datastore
         */
        if (residentKeyConfig.equalsIgnoreCase("true")) {
            String _userHandleIdStr = byteArrayToAsciiString(_userHandleBytes);
            userName = searchUserNameWithAttrValue(_userHandleIdStr, "entryUUID");
            authenticators = webauthnService.getAuthenticators(_userHandleBytes);
            if (authenticators.isEmpty()) {
                DEBUG.error("WebAuthnAuthenticate.verifyAuthenticatorCallback() :  User authenticators not found");
                throw new MessageLoginException(BUNDLE_NAME, "msgNoDevice", null);
            }
        }
        
        WebAuthnAuthenticator _selectedAuthenticator = null;
        for (WebAuthnAuthenticator authenticator : authenticators) {
            if (authenticator.isSelected(_responseJson.getRawId())) {
                _selectedAuthenticator = authenticator;
                break;
            }
        }
        if (_selectedAuthenticator == null) {
            DEBUG.error("WebAuthnAuthenticate.verifyAuthenticatorCallback() :  User authenticator is not detected");
            throw new AuthLoginException(BUNDLE_NAME, "noDeviceDetected", null);
        }
        
        webauthnValidator.validateGetResponse(getValidationConfig(), _responseJson,
                _selectedAuthenticator, DEBUG);
        
        boolean _storeResult = webauthnService.updateCounter(_selectedAuthenticator);
        if (_storeResult) {
            setAuthLevel(authLevel);
            if (DEBUG.messageEnabled()) {
                DEBUG.message("WebAuthn Authentication success");
            }
            validatedUserID = userName;
            return STATE_COMPLETE;
        } else {
            DEBUG.error("WebAuthnAuthenticate.verifyAuthenticatorCallback() :  Error updating counter");
            throw new AuthLoginException(BUNDLE_NAME, "storeError", null);
        }
    }
    
    /**
     * Searches for an account with userHandle userID in the organization organization.
     * 
     * @param attributeValue The attributeValue to compare when searching for an identity.
     * @param attributeName that name of where the identity will be looked up.
     * @return The user name.
     * @throws AuthLoginException
     */
    private String searchUserNameWithAttrValue(String attributeValue, String attributeName) throws AuthLoginException {
 
        if (DEBUG.messageEnabled()) {
            DEBUG.message("WebAuthnAuthenticate.searchUserNameWithAttrValue() :  attributeName={}  attributeValue={}",
                    attributeName, attributeValue);
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
                        DEBUG.message("WebAuthnAuthenticate.searchUserNameWithAttrValue() :  {} result(s) obtained",
                                _results.size());
                    }
                    if (_results.size() > 1) {
                        DEBUG.error("WebAuthnAuthenticate.searchUserNameWithAttrValue() : There are multiple target users");
                        throw new AuthLoginException(BUNDLE_NAME, "multipleUserFound", null);
                    }
                    AMIdentity _userDNId = _results.iterator().next();
                    if (_userDNId != null) {
                        if (DEBUG.messageEnabled()) {
                            DEBUG.error("WebAuthnAuthenticate.searchUserNameWithAttrValue() : user={}",
                                    _userDNId.getUniversalId());
                        }
                        return _userDNId.getName();
                    }
                }
            }
        } catch (IdRepoException idrepoex) {
            DEBUG.error("WebAuthnAuthenticate.searchUserNameWithAttrValue() : An exception occurred while searching for user.",
                    idrepoex);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, idrepoex);
        } catch (SSOException ssoe) {
            DEBUG.error("WebAuthnAuthenticate.searchUserNameWithAttrValue() : An exception occurred while searching for user.",
                    ssoe);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ssoe);
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message(BUNDLE_NAME + " No results were found !");
        }
        throw new AuthLoginException(BUNDLE_NAME, "noUserIdentified", null);
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
