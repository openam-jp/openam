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

import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnService;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnServiceFactory;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

/**
 * WebAuthn (Authenticate) Authentication Module.
 */
public class WebauthnAuthenticate extends AbstractWebAuthnModule {

    public static final String BUNDLE_NAME = "amAuthWebauthnAuthenticate";
    private static final Debug DEBUG = Debug.getInstance(WebauthnAuthenticate.class.getSimpleName());
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
    // Configuration Strings for Authenticate
    private static final String USE_MFA = "iplanet-am-auth-Webauthn-useMfa";

    // Configuration Parameters for Authenticate
    private String useMfaConfig = "";

    // Webauthn
    private Set<WebAuthnAuthenticator> authenticators = null;
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
            nextState = selectLoginType();
            break;
        case LOGIN_START:
            nextState = handlePasswordLessLoginStartCallbacks(callbacks);
            break;
        case LOGIN_SCRIPT:
            nextState = verifyAuthenticatorCallback(callbacks);
            break;
        case RESIDENTKEY_LOGIN_START:
            nextState = handleResidentKeyLoginStartCallbacks(callbacks);
            break;
        case MFA_LOGIN_START:
            nextState = handleMfaLoginStartCallbacks(callbacks);
            break;
        default:
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }

        return nextState.intValue();
    }

    /**
     * Select login type (PasswordLess / ResidentKey / MFA).
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private WebauthnAuthenticateModuleState selectLoginType() throws AuthLoginException {
        
        WebauthnAuthenticateModuleState nextState;
        
        try {
            String realm = DNMapper.orgNameToRealmName(getRequestOrg());
            webauthnService = webauthnServiceFactory.create(realm);
        } catch (SSOException|SMSException ex) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
        }
        
        if (useMfaConfig.equalsIgnoreCase("true")) {
            if (userName == null) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
            nextState = WebauthnAuthenticateModuleState.MFA_LOGIN_START;
        } else if (residentKeyConfig.equalsIgnoreCase("true")) {
            nextState = WebauthnAuthenticateModuleState.RESIDENTKEY_LOGIN_START;
        } else {
            nextState = WebauthnAuthenticateModuleState.LOGIN_START;
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
    private WebauthnAuthenticateModuleState handlePasswordLessLoginStartCallbacks(Callback[] callbacks) 
            throws AuthLoginException {

        if (DEBUG.messageEnabled()) {
            DEBUG.message("ThisState = WebauthnAuthenticateModuleStat.LOGIN_START");
        }

        userName = ((NameCallback) callbacks[0]).getName();
        
        getStoredCredentialId();
        
        createLoginScript();

        return WebauthnAuthenticateModuleState.LOGIN_SCRIPT;
    }
    
    /**
     * Handle callbacks of resident key login starting.
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private WebauthnAuthenticateModuleState handleResidentKeyLoginStartCallbacks(Callback[] callbacks)
            throws AuthLoginException {

        if (DEBUG.messageEnabled()) {
            DEBUG.message("ThisState = WebauthnAuthenticateModuleStat.RESIDENTKEY_LOGIN_START");
        }

        createLoginScript();

        return WebauthnAuthenticateModuleState.LOGIN_SCRIPT;
    }

    /**
     * Handle callbacks of MFA login starting.
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private WebauthnAuthenticateModuleState handleMfaLoginStartCallbacks(Callback[] callbacks)
            throws AuthLoginException {

        if (DEBUG.messageEnabled()) {
            DEBUG.message("ThisState = WebauthnAuthenticateModuleStat.MFA_LOGIN_START");
        }

        getStoredCredentialId();
        
        createLoginScript();
        
        return WebauthnAuthenticateModuleState.LOGIN_SCRIPT;
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
        try {
            byte[] entryUUID = lookupByteData("entryUUID");
            authenticators = webauthnService.getAuthenticators(entryUUID);
            if (authenticators.isEmpty()) {
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
        } catch (AuthLoginException ex) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
        }
    }

    /**
     * Create logn javascript (credentials.get).
     * 
     * @throws AuthLoginException
     */
    private void createLoginScript() throws AuthLoginException {

        // Generate challenge
        byte[] _challengeBytes = webauthnValidator.generateChallenge();

        // navigator.credentials.get Options
        //redidentkey dosn't need stored credentialid(authenticators = null).
        CredentialsGetOptions credentialsGetOptions = new CredentialsGetOptions(
                authenticators,
                userVerificationConfig,
                _challengeBytes,
                timeoutConfig,
                residentKeyConfig);

        // Replace Callback to send Generated Javascript that include get options.
        // only for nextState LOGIN_SCRIPT
        Callback creadentialsGetCallback = new ScriptTextOutputCallback(
                credentialsGetOptions.generateCredntialsGetScriptCallback());
        replaceCallback(WebauthnAuthenticateModuleState.LOGIN_SCRIPT.intValue(), 0, creadentialsGetCallback);
    }

    /**
     * Verify Authenticator(browser) Response Credentials for Authentication
     * 
     * @param callbacks The callbacks.
     * @return A value indicating the next state.
     * @throws AuthLoginException
     */
    private WebauthnAuthenticateModuleState verifyAuthenticatorCallback(Callback[] callbacks)
            throws AuthLoginException {
        
        if (DEBUG.messageEnabled()) {
            DEBUG.message("ThisState = WebauthnAuthenticateModuleStat.LOGIN_SCRIPT");
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

        /*
         * Map Callback Json to Object
         */
        WebauthnJsonCallback _responseJson;
        try {
            _responseJson = OBJECT_MAPPER.readValue(_webauthnHiddenCallback, WebauthnJsonCallback.class);
            if (DEBUG.messageEnabled()) {
                DEBUG.message("id Base64Url = " + _responseJson.getId());
                DEBUG.message("_responseJson.getUserHandle() = " + _responseJson.getUserHandle());
            }
        } catch (IOException e) {
            DEBUG.error("Webauthn.process(): JSON parse error", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        }

        byte[] _userHandleBytes = Base64.getDecoder().decode(_responseJson.getUserHandle());
        byte[] _rawIdBytes = Base64.getDecoder().decode(_responseJson.getRawId());
        
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
                throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
            }
        }
        
        WebAuthnAuthenticator _selectedAuthenticator = null;
        for (WebAuthnAuthenticator authenticator : authenticators) {
            if (authenticator.isSelected(Base64url.encode(_rawIdBytes))) {
                _selectedAuthenticator = authenticator;
                break;
            }
        }
        if (_selectedAuthenticator == null) {
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
        }
        
        boolean _storeResult = webauthnService.updateCounter(_selectedAuthenticator);
        if (_storeResult) {
            setAuthLevel(authLevel);
            if (DEBUG.messageEnabled()) {
                DEBUG.message("Webauthn Authentication success");
            }
            validatedUserID = userName;
            return WebauthnAuthenticateModuleState.COMPLETE;
        } else {
            DEBUG.error("updateCounter error");
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
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
                    if (_results.size() > 1) {
                        throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
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
        throw new AuthLoginException(BUNDLE_NAME, "authFailed", null);
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
