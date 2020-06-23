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
 * Copyright 2019-2020 Open Source Solution Technology Corporation
 */

package jp.co.osstech.openam.authentication.modules.webauthn;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.shared.debug.Debug;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.exception.ValidationException;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

/**
 * The Implementation class for WebAuthn Validation using WebAuthn4J.
 */
public class WebAuthn4JValidatorImpl implements WebAuthnValidator {

    private WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

    private Challenge generatedChallenge = new DefaultChallenge();

    @Override
    public byte[] generateChallenge() {
        return ArrayUtil.clone(generatedChallenge.getValue());
    }

    @Override
    public WebAuthnAuthenticator validateCreateResponse(WebAuthnValidatorConfig config, WebAuthnJsonCallback responseJson,
            byte[] userHandleIdBytes, Debug debug) throws AuthLoginException {

        try {
            /*
             * Validation authenticator response This must be change to W3C verification
             * flow. This time use webauthn4j library to END
             * START============================.
             */
            byte[] _clientDataJsonBytes = Base64UrlUtil.decode(responseJson.getClientDataJSON());
            byte[] _attestationObjectBytes = Base64UrlUtil.decode(responseJson.getAttestationObject());
            String _clientExtensionJSON = null;
            Set<String> _transports = null;

            Origin _origin = new Origin(config.getOrigin());
            String _rpId = _origin.getHost();

            byte[] _tokenBindingId = null;
            ServerProperty _serverProperty = new ServerProperty(_origin, _rpId, generatedChallenge, _tokenBindingId);

            boolean _userVerificationRequired = config.isVerificationRequired(); 
            boolean _userPresenceRequired = true; 
            List<String> _expectedExtensionIds = Collections.emptyList(); //OpenAM desn't use extension now.

            RegistrationRequest _registrationRequest = new RegistrationRequest(_attestationObjectBytes, _clientDataJsonBytes, 
                    _clientExtensionJSON, _transports);
            RegistrationParameters _registrationParameters = new RegistrationParameters(_serverProperty, _userVerificationRequired, 
                    _userPresenceRequired, _expectedExtensionIds);

            RegistrationData _registrationData;
            try{
                _registrationData = webAuthnManager.parse(_registrationRequest);
                webAuthnManager.validate(_registrationData, _registrationParameters);
            } catch (DataConversionException e){
                // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
                throw e;
            } catch (ValidationException e){
                // If you would like to handle WebAuthn data validation error, please catch ValidationException
                throw e;
            }

            // CredentialId = RegistrationData --> AttestationObject --> AuthenticatorData -->
            //    AttstedCredentialData --> CredentialId
            byte[] _attestedCredentialIdBytes = ArrayUtil.clone(_registrationData.getAttestationObject().getAuthenticatorData()
                    .getAttestedCredentialData().getCredentialId());

            // COSEKey = RegistrationData --> AttestationObject --> AuthenticatorData -->
            //    AttstedCredentialData --> COSEKey
            COSEKey _coseKey = _registrationData.getAttestationObject().getAuthenticatorData()
                    .getAttestedCredentialData().getCOSEKey();

            // Counter = RegistrationData --> AttestationObject --> AuthenticatorData --> Counter
            long _attestedCounter = _registrationData.getAttestationObject().getAuthenticatorData().getSignCount();

            ObjectConverter _objectConverter = new ObjectConverter();
            CborConverter _cborConverter = _objectConverter.getCborConverter();
            WebAuthnAuthenticator amAuthenticator = new WebAuthnAuthenticator(
                    Base64UrlUtil.encodeToString(_attestedCredentialIdBytes),
                    _cborConverter.writeValueAsBytes(_coseKey),
                    new Long(_attestedCounter), userHandleIdBytes);

            return amAuthenticator;

        } catch (Exception ex) {
            debug.error("WebAuthnValidator.validateCreateResponse : Error validating response. User handle is {}",
                    WebAuthnAuthenticator.getUserIDAsString(userHandleIdBytes), ex);
            throw new AuthLoginException(WebAuthnRegister.BUNDLE_NAME, "libraryError", null, ex);
        }
    }

    @Override
    public void validateGetResponse(WebAuthnValidatorConfig config, WebAuthnJsonCallback responseJson,
            WebAuthnAuthenticator amAuthenticator, Debug debug) throws AuthLoginException {

        try {
            /*
             * Validation authenticator response This must be change to W3C verification
             * flow. Use webauthn4j library to END
             * START============================.
             */
            byte[] _rawId = Base64UrlUtil.decode(responseJson.getRawId());
            byte[] _userHandle = Base64UrlUtil.decode(responseJson.getUserHandle());
            byte[] _authenticatorDataBytes = Base64UrlUtil.decode(responseJson.getAuthenticatorData());
            byte[] _clientDataJsonBytes = Base64UrlUtil.decode(responseJson.getClientDataJSON());
            String _clientExtensionJSON = null;
            byte[] _signatureBytes = Base64UrlUtil.decode(responseJson.getSignature());

            Origin _origin = new Origin(config.getOrigin());
            String _rpId = _origin.getHost();
            byte[] _tokenBindingId = null; 
            ServerProperty _serverProperty = new ServerProperty(_origin, _rpId, generatedChallenge, _tokenBindingId);

            boolean _userVerificationRequired = config.isVerificationRequired(); 
            boolean _userPresenceRequired = true; 
            List<String> _expectedExtensionIds = Collections.emptyList(); //OpenAM desn't use extension now.

            // OpenAM didn't store aaguid now. Use ZERO AAGUID.
            AAGUID _aaguid = AAGUID.ZERO;

            //credentialPublicKey was stored as COSEKey byte[] data at registration time.
            ObjectConverter _objectConverter = new ObjectConverter();
            CborConverter _cborConverter = _objectConverter.getCborConverter();
            COSEKey _coseKey =
                    _cborConverter.readValue(amAuthenticator.getPublicKey(), COSEKey.class);

            final AttestedCredentialData _storedAttestedCredentialData =
                    new AttestedCredentialData(_aaguid,
                            Base64UrlUtil.decode(amAuthenticator.getCredentialID()), _coseKey);
            final AttestationStatement _noneAttestationStatement = new NoneAttestationStatement();
            final long _storedCounter = amAuthenticator.getSignCount();
            Authenticator _authenticator = new AuthenticatorImpl(_storedAttestedCredentialData,
                    _noneAttestationStatement, _storedCounter);

            AuthenticationRequest _authenticationRequest =
                    new AuthenticationRequest(
                            _rawId,
                            _userHandle,
                            _authenticatorDataBytes,
                            _clientDataJsonBytes,
                            _clientExtensionJSON,
                            _signatureBytes
                    );
            AuthenticationParameters _authenticationParameters =
                    new AuthenticationParameters(
                            _serverProperty,
                            _authenticator,
                            _userVerificationRequired,
                            _userPresenceRequired,
                            _expectedExtensionIds
                    );

            AuthenticationData _authenticationData;
            try{
                _authenticationData = webAuthnManager.parse(_authenticationRequest);
                webAuthnManager.validate(_authenticationData, _authenticationParameters);
            } catch (DataConversionException e){
                // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
                throw e;
            } catch (ValidationException e){
                // If you would like to handle WebAuthn data validation error, please catch ValidationException
                throw e;
            }

            // Update Counter = AuthenticationData --> AuthenticatorData --> Counter
            amAuthenticator.setSignCount(_authenticationData.getAuthenticatorData().getSignCount());

        } catch (Exception ex) {
            debug.error("WebAuthnValidator.validateGetResponse : Error validating response. User handle is {}",
                    WebAuthnAuthenticator.getUserIDAsString(amAuthenticator.getUserID()), ex);
            throw new AuthLoginException(WebAuthnAuthenticate.BUNDLE_NAME, "libraryError", null, ex);
        }
    }
}
