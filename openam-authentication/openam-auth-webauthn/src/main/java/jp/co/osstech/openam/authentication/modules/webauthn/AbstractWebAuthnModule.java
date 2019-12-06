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

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import javax.security.auth.Subject;

import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.devices.services.AuthenticatorDeviceServiceFactory;
import org.forgerock.openam.utils.CollectionUtils;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnService;
import jp.co.osstech.openam.core.rest.devices.services.webauthn.AuthenticatorWebAuthnServiceFactory;

/**
 * Abstract Class for WebAuthnRegister / WebAuthnAuthenticate
 */
public abstract class AbstractWebAuthnModule extends AMLoginModule {

    // Common Configuration Strings
    protected static final String RP_NAME = "iplanet-am-auth-Webauthn-rp";
    protected static final String ORIGIN = "iplanet-am-auth-Webauthn-origin";
    protected static final String RESIDENTKEY = "iplanet-am-auth-Webauthn-residentKey";
    protected static final String USER_VERIFICATION = "iplanet-am-auth-Webauthn-userVerification";
    protected static final String TIMEOUT = "iplanet-am-auth-Webauthn-timeout";
    protected static final String DISPLAY_NAME_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-displayNameAttributeName";
    protected static final String AUTH_LEVEL = "iplanet-am-auth-Webauthn-auth-level";

    // Default Values.
    private static final int DEFAULT_AUTH_LEVEL = 0;

    // Common Configuration Parameters
    protected String rpNameConfig = "";
    protected String originConfig = "";
    protected String residentKeyConfig = "";
    protected String userVerificationConfig = "";
    protected String timeoutConfig = "";
    protected String displayNameAttributeNameConfig = "";

    // Common
    protected ResourceBundle bundle;
    protected String userName;
    protected int authLevel;

    // user's valid ID and principal
    protected String validatedUserID;
    protected WebAuthnPrincipal userPrincipal;

    // WebAuthn
    protected final AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService> webauthnServiceFactory =
            InjectorHolder.getInstance(Key.get(
                    new TypeLiteral<AuthenticatorDeviceServiceFactory<AuthenticatorWebAuthnService>>(){},
                    Names.named(AuthenticatorWebAuthnServiceFactory.FACTORY_NAME)));
    protected AuthenticatorWebAuthnService webauthnService;
    protected WebAuthnValidator webauthnValidator = InjectorHolder.getInstance(WebAuthnValidator.class);

    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        Debug debug = getDebugInstance();

        java.util.Locale locale = getLoginLocale();
        bundle = amCache.getResBundle(getBundleName(), locale);
        if (debug.messageEnabled()) {
            debug.message("WebAuthn getting resource bundle for locale: " + locale);
        }

        this.rpNameConfig = CollectionHelper.getMapAttr(options, RP_NAME);
        this.originConfig = CollectionHelper.getMapAttr(options, ORIGIN);
        this.residentKeyConfig = CollectionHelper.getMapAttr(options, RESIDENTKEY);
        this.userVerificationConfig = CollectionHelper.getMapAttr(options, USER_VERIFICATION);
        this.timeoutConfig = CollectionHelper.getMapAttr(options, TIMEOUT);
        this.displayNameAttributeNameConfig = CollectionHelper.getMapAttr(options, DISPLAY_NAME_ATTRIBUTE_NAME);

        this.authLevel = CollectionHelper.getIntMapAttr(options, AUTH_LEVEL, DEFAULT_AUTH_LEVEL, debug);

    }

    @Override
    public Principal getPrincipal() {
        if (userPrincipal != null) {
            return userPrincipal;
        } else if (validatedUserID != null) {
            userPrincipal = new WebAuthnPrincipal(validatedUserID);
            return userPrincipal;
        } else {
            return null;
        }
    }

    @Override
    public void destroyModuleState() {
        validatedUserID = null;
        userPrincipal = null;
    }

    @Override
    public void nullifyUsedVars() {
        bundle = null;
        userName = null;
    }

    /**
     * Get user identity object.
     * 
     * @return user identity object.
     * @throws AuthLoginException
     */
    protected AMIdentity getIdentity() throws AuthLoginException {
        Debug debug = getDebugInstance();

        AMIdentityRepository _amIdRepo = getAMIdentityRepository(getRequestOrg());

        IdSearchControl _idsc = new IdSearchControl();
        _idsc.setAllReturnAttributes(true);
        Set<AMIdentity> _results = Collections.emptySet();

        try {
            IdSearchResults _searchResults = _amIdRepo.searchIdentities(IdType.USER, userName, _idsc);
            if (_searchResults != null) {
                _results = _searchResults.getSearchResults();
            }
        } catch (SSOException e) {
            debug.error("WebAuthn.getIdentity : Error searching Identities with username '{}' ", userName, e);
        } catch (IdRepoException e) {
            debug.error("WebAuthn.getIdentity : Error searching Identities with username '{}' ", userName, e);
        }

        if (_results.isEmpty()) {
            debug.error("WebAuthn.getIdentity : User '{}' is not found", userName);
            throw new AuthLoginException(getBundleName(), "noUserFound", null);
        } else if (_results.size() > 1) {
            debug.error("WebAuthn.getIdentity : More than one user found for the userName '{}'", userName);
            throw new AuthLoginException(getBundleName(), "multipleUserFound", null);
        } else {
            return _results.iterator().next();
        }
    }

    /**
     * Lookup String data from user data store.
     * 
     * @param attributeName The attribute name.
     * @return String data.
     * @throws AuthLoginException
     */
    protected String lookupStringData(String attributeName) throws AuthLoginException {
        Debug debug = getDebugInstance();
        Set<String> _attributes = Collections.emptySet();

        try {
            _attributes = getIdentity().getAttribute(attributeName);
        } catch (SSOException e) {
            debug.error("WebAuthn.lookupStringData() : Error getting user {} attribute", userName, e);
            throw new AuthLoginException(getBundleName(), "userAttributeError", null, e);
        } catch (IdRepoException e) {
            debug.error("WebAuthn.lookupStringData() : Error getting user {} attribute", userName, e);
            throw new AuthLoginException(getBundleName(), "userAttributeError", null, e);
        }

        String _attribute = "";

        if (CollectionUtils.isNotEmpty(_attributes)) {
            _attribute = _attributes.iterator().next();
        }
        return _attribute;
    }

    /**
     * Lookup Byte data from user data store.
     * 
     * @param attributeName The attribute name.
     * @return Byte data
     * @throws AuthLoginException
     */
    protected byte[] lookupByteData(String attributeName) throws AuthLoginException {
        Debug debug = getDebugInstance();
        Set<String> _attribute = CollectionUtils.asSet(attributeName);

        try {
            Map<String, byte[][]> _lookupByteData = getIdentity().getBinaryAttributes(_attribute);
            return _lookupByteData.get(attributeName)[0];
        } catch (SSOException e) {
            debug.error("WebAuthn.lookupByteData() : Error getting user {} attribute", userName, e);
            throw new AuthLoginException(getBundleName(), "userAttributeError", null, e);
        } catch (IdRepoException e) {
            debug.error("WebAuthn.lookupByteData() : Error getting user {} attribute", userName, e);
            throw new AuthLoginException(getBundleName(), "userAttributeError", null, e);
        }
    }

    /**
     * Convert byte array to ASCII String. This method is used to convert
     * entryUUID for search user(userHandle=entryUUID).
     * 
     * @param bytes The byte array.
     * @return ASCII String.
     */
    protected String byteArrayToAsciiString(byte[] bytes) {
        StringBuffer _sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            _sb.append( Character.toChars(bytes[i]) );
        }
        return _sb.toString();
    }

    /**
     * Get the configuration for WebAuthn validation
     * 
     * @return The configuration for WebAuthn validation.
     */
    protected WebAuthnValidatorConfig getValidationConfig() {
        boolean verificationRequired;
        if (userVerificationConfig.equalsIgnoreCase("required")) {
            verificationRequired = true;
        } else {
            verificationRequired = false;
        }
        return new WebAuthnValidatorConfig(originConfig, verificationRequired);
    }

    /**
     * Get debug instance.
     * @return The debug instance.
     */
    protected abstract Debug getDebugInstance();

    /**
     * Get resource bundle name.
     * @return The resource bundle name.
     */
    protected abstract String getBundleName();
}
