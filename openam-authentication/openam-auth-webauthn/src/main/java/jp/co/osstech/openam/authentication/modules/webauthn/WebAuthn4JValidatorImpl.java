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

import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.shared.debug.Debug;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnRegistrationContext;
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
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;

import jp.co.osstech.openam.core.rest.devices.services.webauthn.WebAuthnAuthenticator;

/**
 * The Implementation class for WebAuthn Validation using WebAuthn4J.
 */
public class WebAuthn4JValidatorImpl implements WebAuthnValidator {
    
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
            byte[] _attestationObjectBytes = Base64UrlUtil.decode(responseJson.getAttestationObject());
            byte[] _clientDataJsonBytes = Base64UrlUtil.decode(responseJson.getClientDataJSON());
            
            Origin _origin = new Origin(config.getOrigin());
            String _rpId = _origin.getHost();

            byte[] _tokenBindingId = null;

            // rp:id = origin
            ServerProperty serverProperty = new ServerProperty(_origin, _rpId, generatedChallenge, _tokenBindingId);

            WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(_clientDataJsonBytes,
                    _attestationObjectBytes, serverProperty, config.isVerificationRequired());
            WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator = WebAuthnRegistrationContextValidator
                    .createNonStrictRegistrationContextValidator();
            WebAuthnRegistrationContextValidationResponse response = webAuthnRegistrationContextValidator
                    .validate(registrationContext);

            // CredentialId <-- AttestedCredentialData <--AuthenticationData
            // <--AttestationObject
            byte[] attestedCredentialIdBytes = ArrayUtil.clone(response.getAttestationObject().getAuthenticatorData()
                    .getAttestedCredentialData().getCredentialId());

            // COSEKey <-- AttestedCredentialData <--AuthenticationData
            // <--AttestationObject
            COSEKey coseKey = response.getAttestationObject().getAuthenticatorData()
                    .getAttestedCredentialData().getCOSEKey();

            // Counter <--AuthenticationData <--AttestationObject
            long attestedCounter = response.getAttestationObject().getAuthenticatorData().getSignCount();
            
            CborConverter _cborConverter = new CborConverter();
            WebAuthnAuthenticator amAuthenticator = new WebAuthnAuthenticator(
                    Base64UrlUtil.encodeToString(attestedCredentialIdBytes),
                    _cborConverter.writeValueAsBytes(coseKey),
                    new Long(attestedCounter), userHandleIdBytes);
            
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
            byte[] rawIdBytes = Base64UrlUtil.decode(responseJson.getRawId());
            byte[] authenticatorDataBytes = Base64UrlUtil.decode(responseJson.getAuthenticatorData());
            byte[] clientDataJsonBytes = Base64UrlUtil.decode(responseJson.getClientDataJSON());
            byte[] signatureBytes = Base64UrlUtil.decode(responseJson.getSignature());
            
            Origin _origin = new Origin(config.getOrigin());
            String _rpId = _origin.getHost();
            byte[] _tokenBindingId = null; /* now set tokenBindingId null */
            ServerProperty serverProperty = new ServerProperty(_origin, _rpId, generatedChallenge, _tokenBindingId);

            WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(rawIdBytes,
                    clientDataJsonBytes, authenticatorDataBytes, signatureBytes, serverProperty,
                    config.isVerificationRequired());

            // OpenAM didn't store aaguid now. Use ZERO AAGUID.
            AAGUID _aaguid = AAGUID.ZERO;
            
            //credentialPublicKey was stored as COSEKey byte[] data at registration time.
            CborConverter _cborConverter = new CborConverter();
            COSEKey coseKey = 
                    _cborConverter.readValue(amAuthenticator.getPublicKey(), COSEKey.class);

            final AttestedCredentialData storedAttestedCredentialData = 
                    new AttestedCredentialData(_aaguid, 
                            Base64UrlUtil.decode(amAuthenticator.getCredentialID()), coseKey);
            final AttestationStatement noneAttestationStatement = new NoneAttestationStatement();
            final long storedCounter = amAuthenticator.getSignCount();
            Authenticator authenticator = new AuthenticatorImpl(storedAttestedCredentialData,
                    noneAttestationStatement, storedCounter);

            WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator = new WebAuthnAuthenticationContextValidator();

            WebAuthnAuthenticationContextValidationResponse response = webAuthnAuthenticationContextValidator
                    .validate(authenticationContext, authenticator);
            
            // Update counter
            amAuthenticator.setSignCount(response.getAuthenticatorData().getSignCount());
        
        } catch (Exception ex) {
            debug.error("WebAuthnValidator.validateGetResponse : Error validating response. User handle is {}", 
                    WebAuthnAuthenticator.getUserIDAsString(amAuthenticator.getUserID()), ex);
            throw new AuthLoginException(WebAuthnAuthenticate.BUNDLE_NAME, "libraryError", null, ex);
        }
    }
}
