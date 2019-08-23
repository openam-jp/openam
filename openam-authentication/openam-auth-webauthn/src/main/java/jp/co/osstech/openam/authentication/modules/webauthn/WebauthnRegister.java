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

import java.io.IOException;
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
import java.util.Base64;
import java.util.Base64.Decoder;
import java.lang.Byte;

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

import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.utils.qr.ErrorCorrectionLevel;
import org.forgerock.util.encode.Base64url;

public class WebauthnRegister extends AMLoginModule {
	
	private static final String BUNDLE_NAME = "amAuthWebauthnRegister";
	private final static Debug DEBUG = Debug.getInstance(WebauthnRegister.class.getSimpleName());
	
	private ResourceBundle bundle;
	private Map sharedState;

	// user's valid ID and principal
	private String validatedUserID;
	private WebauthnPrincipal userPrincipal;

	// Configurations
	private Map options;

	private String id;
	private String CredentialId;
	//private String getCredentialId;
	//private String createCredentialId;
	private String rawId;
	private static String userName = "";
	private String createCred;
	private String userCred;
	private String displayName;
	private Map userAttrs;
	private StringBuilder storedChallenge;
	private StringBuilder idArray;
	
	private String createCredentialId;
	private String createAttestationObject;
	private String createClientDataJSON;
	
	private String getCredentialId;
	private String getSignature;
	private String getClientDataJSON;
	private String getAuthenticatorData;
	private String getType;
	private String getUserHandle;
	
	// Service Configuration Parameters
	private String rpConfig = null;
	private String attestationConfig = null;
	private String attachmentConfig = null;
	private String residentKeyConfig = null;
	private String userVerificationConfig = null;
	private String credentialIdAttributeNameConfig = null;
	private String keyAttributeNameConfig = null;	
	private String displayNameAttributeNameConfig = null;
	
	// Service Configuration Strings
	private static final String RP = "iplanet-am-auth-Webauthn-rp";
	private static final String ATTESTATION = "iplanet-am-auth-Webauthn-attestation";
	private static final String ATTACHMENT = "iplanet-am-auth-Webauthn-attachment";
	private static final String RESIDENTKEY = "iplanet-am-auth-Webauthn-residentKey";
	private static final String USER_VERIFICATION = "iplanet-am-auth-Webauthn-userVerification";
	private static final String CREDENTIALID_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-credentialIdAttributeName";
	private static final String KEY_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-keyAttributeName";
	private static final String DISPLAY_NAME_ATTRIBUTE_NAME = "iplanet-am-auth-Webauthn-displayNameAttributeName";
	private static final String AUTH_LEVEL = "iplanet-am-auth-Webauthn-auth-level";
	
	// Default Values.
   private static final int DEFAULT_AUTH_LEVEL = 0;

	private boolean getCredentialsFromSharedState;
	private Callback[] callbacks;
	private Set<String> userSearchAttributes = Collections.emptySet();
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
	/**
	 * Initializes this <code>LoginModule</code>.
	 *
	 * @param subject the <code>Subject</code> to be authenticated.
	 * @param sharedState shared <code>LoginModule</code> state.
	 * @param options options specified in the login.
	 *        <code>Configuration</code> for this particular
	 *        <code>LoginModule</code>.
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
		
		this.rpConfig = CollectionHelper.getMapAttr(options, RP);
		this.attestationConfig = CollectionHelper.getMapAttr(options, ATTESTATION);
		this.attachmentConfig = CollectionHelper.getMapAttr(options, ATTACHMENT);
		this.residentKeyConfig = CollectionHelper.getMapAttr(options, RESIDENTKEY);
		this.userVerificationConfig = CollectionHelper.getMapAttr(options, USER_VERIFICATION);
		this.credentialIdAttributeNameConfig = CollectionHelper.getMapAttr(options, CREDENTIALID_ATTRIBUTE_NAME);
		this.keyAttributeNameConfig = CollectionHelper.getMapAttr(options, KEY_ATTRIBUTE_NAME);
		this.displayNameAttributeNameConfig = CollectionHelper.getMapAttr(options, DISPLAY_NAME_ATTRIBUTE_NAME);
		
		if (DEBUG.messageEnabled()) {
			DEBUG.message("Webauthn module parameter are "
					+ ", rp = " + rpConfig
					+ ", attestation = " + attestationConfig
					+ ", attachment = " + attachmentConfig
					+ ", residentKey = " + residentKeyConfig
					+ ", userVerification = " + userVerificationConfig
					+ ", credentialIdAttributeName = " + credentialIdAttributeNameConfig
					+ ", displayNameAttributeName = " + displayNameAttributeNameConfig
					+ ", keyAttributeName = " + keyAttributeNameConfig
					);
		}
		
		/*
		 * Make Service for store challenge and other resouces
		 * #TODO write code
		 * 
		 */
        userName = (String) sharedState.get(getUserKey());
        if (DEBUG.messageEnabled()) {
              DEBUG.message("userName: " + userName);
          }

		
	}

	/**
	 * Takes an array of submitted <code>Callback</code>,
	 * process them and decide the order of next state to go.
	 * Return STATE_SUCCEED if the login is successful, return STATE_FAILED
	 * if the LoginModule should be ignored.
	 *
	 * @param callbacks an array of <code>Callback</cdoe> for this Login state
	 * @param state order of state. State order starts with 1.
	 * @return int order of next state. Return STATE_SUCCEED if authentication
	 *         is successful, return STATE_FAILED if the
	 *         LoginModule should be ignored.
	 * @throws AuthLoginException
	 */
	public int process(Callback[] callbacks, int state)
			throws AuthLoginException {
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

			/*
			 *  Pre Authentication for Key Registration
			 *  expect REG_SCRIPT
			 *  lookup DisplayName
			 */
	          
			if (userName != null) {
				nextState = WebauthnRegisterModuleState.REG_SCRIPT;
			} else {
			    nextState = WebauthnRegisterModuleState.REG_START;
			}
			
			//generate 32byte challenge
			//generate 16byte id
			try {
				storedChallenge = genBytesArrayStr(32);
				idArray = genBytesArrayStr(16);
			} catch(GeneralSecurityException e) {
				throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
			}

			// navigator.credentials.create Options for javascript
			String createCredntialsJavascript = getCreateCredJavascript(
					rpConfig,
					idArray,
					userName, 
					displayName, 
					attestationConfig, 
					attachmentConfig, 
					residentKeyConfig, 
					userVerificationConfig,
					storedChallenge
					);

			if (DEBUG.messageEnabled()) {
				DEBUG.message("createCredntialsJavascpt is " + createCredntialsJavascript);
			}

			// Replace Callback to send Generated Javascript that include create options.
			// only for nextState REG_SCRIPT
			Callback createCreadentialsCallback = new ScriptTextOutputCallback(createCredntialsJavascript);
			replaceCallback(WebauthnRegisterModuleState.REG_SCRIPT.intValue(), 1, createCreadentialsCallback);

			break;

		case REG_SCRIPT:

			if (DEBUG.messageEnabled()) {
				DEBUG.message("ThisState = WebauthnRegisterModuleState.REG_SCRIPT");
			}

			// Registration Verify PublicKey Credentials
			// expect REG_KEY
			try {
				nextState = verifyCreateCred(callbacks);
			} catch (AuthLoginException ex) {
				throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
			}

			break;

		case REG_KEY:
			//maybe no need this state
			if (DEBUG.messageEnabled()) {
				DEBUG.message("ThisState = WebauthnRegisterModuleState.REG_KEY");
			}
			// only display next button and return LOGIN_START
			nextState = WebauthnRegisterModuleState.COMPLETE;

			break;

		}

		return nextState.intValue();
	}


	/**from based membership module
	 * User input value will be store in the callbacks[].
	 * When user click cancel button, these input field should be reset
	 * to blank.
	 */
	private void clearCallbacks(Callback[] callbacks) {
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof NameCallback) {
				NameCallback nc = (NameCallback) callbacks[i];
				nc.setName("");
			}
		}
	}    

	/**from based membership module
	 * Returns <code>Principal</code>.
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

	/**from based membership module
	 * Destroy the module state
	 */
	@Override
	public void destroyModuleState() {
		validatedUserID = null;
	}

	/**from based membership module
	 * Set all the used variables to null
	 */
	@Override
	public void nullifyUsedVars() {
		bundle = null;
		sharedState = null;
		options = null;
		userName = null ;
		userAttrs = null;
		callbacks = null;
	}    

	/*
	 * Verify and Store Authenticator(browser) Response Credentials for Registration
	 * #TODO Verify and Store function are not completed.
	 * 
	 * @param callbacks an array of <code>Callback</cdoe> for this Login state
	 * @return int order of next state. Return 
	 * @throws AuthLoginException
	 */
	private WebauthnRegisterModuleState verifyCreateCred(Callback[] callbacks) throws AuthLoginException {
		
		// read HiddenValueCallback from Authenticator posted
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof HiddenValueCallback) {
				createCred = ((HiddenValueCallback) callbacks[i]).getValue();

				if (createCred == null) {
					return WebauthnRegisterModuleState.REG_START;
				}

			}
		}
		
		if (DEBUG.messageEnabled()) {
		    DEBUG.message("Posted createCred = " + createCred);
		}
		
		/*
		 * Verify json PublicKeyCredential
		 * json to ObjectMapper
		 */

		
		if (StringUtils.isNotEmpty(createCred)) {
			// Deserialize JSON to Map.

			try {
				PublicKeyCredential credjson = OBJECT_MAPPER.readValue(createCred, PublicKeyCredential.class);
				createCredentialId = credjson.getRawId();
				if (DEBUG.messageEnabled()) {
					DEBUG.message("createCredentialId = " + createCredentialId);
				}
				createAttestationObject = credjson.getAttestationObject();
				if (DEBUG.messageEnabled()) {
					DEBUG.message("createAttestationObject = " + createAttestationObject);
				}
				createClientDataJSON = credjson.getClientDataJSON();
				if (DEBUG.messageEnabled()) {
					DEBUG.message("createClientDataJSON = " + createClientDataJSON);
				}
				
			} catch (IOException e) {
				DEBUG.error("Webauthn.process(): JSON parse error", e);
				throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
			} 
		}
		
		/*
		 * temp registration function
		 *  This must be change to W3C verification flow.
		 */
		/*
		 * Store Webauthn informations to user profile
		 */
		try {
			boolean storeResult = false;
			storeResult = storeCredentialId(createCredentialId);
			
			if(storeResult) {
				if (DEBUG.messageEnabled()) {
					DEBUG.message("storeCredentialId was success");
				}
				
				return WebauthnRegisterModuleState.REG_KEY;
				
			} else {
				if (DEBUG.messageEnabled()) {
					DEBUG.message("storeCredentialId was Fail");
				}
				
				return WebauthnRegisterModuleState.REG_START;
				
			}
		} catch (AuthLoginException ex) {
			throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
		}
		
		
		
	}   
	

	/**from based membership module
	 * Returns the password from the PasswordCallback.
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

	/**from based membership module
	 * Returns the input values as a <code>Set<String></code> for different types of Callback.
	 * An empty <code>Set</code> will be returned if there is no value for the
	 * Callback, or the Callback is not supported.
	 */
	private Set<String> getCallbackFieldValues(Callback callback) {
		Set<String> values = new HashSet<String>();

		if (callback instanceof NameCallback) {
			String value = ((NameCallback)callback).getName();
			if (value != null && value.length() != 0) {
				values.add(value);
			}

		} else if (callback instanceof PasswordCallback) {
			String value = getPassword((PasswordCallback)callback);
			if (value != null && value.length() != 0) {
				values.add(value);
			}

		} else if (callback instanceof ChoiceCallback) {
			String[] vals = ((ChoiceCallback)callback).getChoices();
			int[] selectedIndexes = ((ChoiceCallback)callback).getSelectedIndexes();

			for (int i = 0; i < selectedIndexes.length; i++) {
				values.add(vals[selectedIndexes[i]]);
			}
		}

		return values;
	}

	/**from based membership module
	 * Returns the first input value for the given Callback.
	 * Returns null if there is no value for the Callback.
	 */
	private String getCallbackFieldValue(Callback callback) {
		Set<String> values = getCallbackFieldValues(callback);
		Iterator<String> it = values.iterator();

		if (it.hasNext()) {
			return it.next();
		}

		return null;
	} 
	
	/*
	 * from based membership module
	 * 
	 */
	private void updateRegistrationCallbackFields(Callback[] submittedCallbacks) 
			throws AuthLoginException {
		Callback[] origCallbacks = getCallback(WebauthnRegisterModuleState.REG_SCRIPT.intValue());

		for (int c = 0; c < origCallbacks.length; c++) {
			if (origCallbacks[c] instanceof NameCallback) {
				NameCallback nc = (NameCallback) origCallbacks[c];
				nc.setName(((NameCallback) submittedCallbacks[c]).getName());
				replaceCallback(WebauthnRegisterModuleState.REG_KEY.intValue(), c, nc);
			} else {
				continue;
			}
		}
	}
	
	/*
	 * lookup user CredentialId and public key from user data store
	 * @return int order of next state. Return STATE_SUCCEED if authentication
	 *         is successful, return STATE_FAILED if the
	 *         LoginModule should be ignored.
	 * @throws AuthLoginException
	 */
    private String lookupCredentialId() throws AuthLoginException{

        Set<String> CredentialIds = Collections.emptySet();

        try {
        	CredentialIds = getIdentity().getAttribute(credentialIdAttributeNameConfig);
        } catch (SSOException e) {
            DEBUG.error("Webauthn.lookupCredentialId() : Webauthn module exception : ", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        } catch (IdRepoException e) {
            DEBUG.error("Webauthn.lookupCredentialId() : error searching Identities with username : " + userName, e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        }
        
        String CredentialId = null;

        if (org.apache.commons.collections.CollectionUtils.isNotEmpty(CredentialIds)) {
        	CredentialId = CredentialIds.iterator().next();
        }

        return CredentialId;
    }
    
	/*
	 * lookup user DisplayName and public key from user data store
	 * @return int order of next state. Return STATE_SUCCEED if authentication
	 *         is successful, return STATE_FAILED if the
	 *         LoginModule should be ignored.
	 * @throws AuthLoginException
	 */
    private String lookupDisplayName() throws AuthLoginException{

        Set<String> displayNames = Collections.emptySet();

        try {
        	displayNames = getIdentity().getAttribute(displayNameAttributeNameConfig);
        } catch (SSOException e) {
            DEBUG.error("Webauthn.lookupDisplayName() : Webauthn module exception : ", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        } catch (IdRepoException e) {
            DEBUG.error("Webauthn.lookupDisplayName() : error searching DisplayNames with username : " + userName, e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        }
        
        String displayName = null;

        if (org.apache.commons.collections.CollectionUtils.isNotEmpty(displayNames)) {
        	displayName = displayNames.iterator().next();
        }

        return displayName;
    }

    /* Store to user data store
	 * @param String CredentialId
	 * @param String PublicKey #TODO under development
	 * @return boolean
	 * @throws AuthLoginException
	 */ 

    private boolean storeCredentialId(String CredentialId) throws AuthLoginException {
        boolean storeIdResult = false;
        try {
            AMIdentity uid = getIdentity();
            uid.setAttributes(Collections.singletonMap(credentialIdAttributeNameConfig, Collections.singleton(CredentialId)));
            uid.store();
            storeIdResult = true;
        } catch (SSOException e) {
            DEBUG.message("Webauthn.storeCredentialId() : Webauthn module exception : ", e);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, e);
        } catch (IdRepoException ex) {
            DEBUG.message("Webauthn.storeCredentialId() : error sotre Identities with CredentialId : ", ex);
            throw new AuthLoginException(BUNDLE_NAME, "authFailed", null, ex);
        }
        return storeIdResult;
    }
    
    /**
     * This function provides the Javascript for Authenticator registration.
     * #TODO Very Slow String join. It must be changed before release.
     * @param rpConfig                from Service Configuration parameter
     * @param idArray                 generated genBytesArrayStr(16)
     * @param userName                from user data
     * @param displayName             from user data
     * @param attestationConfig       from Service Configuration parameter
     * @param attatiment Config       from Service Configuration parameter
     * @param residentKeyConfig       from Service Configuration parameter
     * @param userVerificationConfig  from Service Configuration parameter
     * @param challengeArrayStr       generated genBytesArrayStr(32)
     * @return The Javascript required for navigator.credentials.create()
     */
    public static String getCreateCredJavascript(
    		String rpConfig,
    		StringBuilder idArray,
    		String userName,
    		String displayName,
    		String attestationConfig,
    		String attatimentConfig,
    		String residentKeyConfig,
    		String userVerificationConfig,
    		StringBuilder challengeArrayStr
           )
    {
    	//Very Slow BUT This is easy understandable code ##TODO must change before release.

        return "require(['jp/co/osstech/openam/server/util/webauthn'], function (webauthn) {\n" +
        "webauthn.createCredential( {" +
        "  publicKey: {" +
        //RP info
        "    rp: {" +
        "      name: '" + rpConfig + "'," +
        "     }," +
        //User info
        "    user: {" +
        "      id: new Uint8Array([" + idArray + "])," +
        "      name: '" + userName + "'," +
        "      displayName: '" + displayName + "'," +
        "     }," +
        //Pubkey param
        "    pubKeyCredParams: [{" +
        "      type: \"public-key\"," +
        "      alg: -7" +
        "       }, {" +
        "      type: \"public-key\"," +
        "      alg: -257" +	       
        "     }]," +
        //Attestation
        "    attestation: '" + attestationConfig + "'," +
        "    authenticatorSelection: {" +
        "      authenticatorAttachment: '" + attatimentConfig + "'," +
        "      requireResidentKey: " + residentKeyConfig + "," +
        "      userVerification: \'" + userVerificationConfig + "'" +
        "    }," +
        //Timeout
        "    timeout: 60000," +
        //Challenge
        "    challenge: new Uint8Array([" + challengeArrayStr + 
        "    ]).buffer" +
        "  } " +
        "} );\n" +
        "});";
    }
    
    /*
     * generate secure random byte[]
     * @param int length
     * @return StringBuilder "," separated array String.
     */
    private StringBuilder genBytesArrayStr(int arrayLength) throws GeneralSecurityException {
    	byte[] byteArray = new byte[arrayLength];
    	SecureRandom.getInstanceStrong().nextBytes(byteArray);
    	
		StringBuilder BytesArrayStr = new StringBuilder();
		
		for (int i=0; i<byteArray.length; i++ ) {
			BytesArrayStr.append(Byte.toUnsignedInt(byteArray[i])).append(",");
		}
		return BytesArrayStr;
    }
    
    /*
     * make secure random challenge byte[]
     * @return byte[] challengeBytes.
     */
    private byte[] makeChallengeBytes() throws GeneralSecurityException {
    	byte[] challengeBytes = new byte[32];
    	SecureRandom.getInstanceStrong().nextBytes(challengeBytes);
    	return challengeBytes;
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

