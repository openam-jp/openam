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
 * Copyright 2026 OSSTech Corporation
 */
package jp.co.osstech.openam.saml2.consent;

import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.exceptions.JweDecryptionException;
import org.forgerock.json.jose.jwe.EncryptedJwt;
import org.forgerock.json.jose.jwe.EncryptionMethod;
import org.forgerock.json.jose.jwe.JweAlgorithm;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.identity.shared.debug.Debug;

/**
 * The class <code>AttributeConsentHistorySerializer</code> provides interface
 * for serializing and deserializing <code>AttributeConsentHistory</code>. The
 * history is encrypted using given public key.
 */
class AttributeConsentHistorySerializer {

    private static final String JSON_KEY_HISTORY = "history";
    private static final String JSON_KEY_SIGNED = "signed";
    private static final Debug DEBUG = Debug.getInstance("SAML2AttributeConsent");

    private static ObjectMapper mapper;
    static {
        mapper = new ObjectMapper();
        mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);
    }

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String signingSecret;
    private JwtBuilderFactory jwtBuilderFactory;

    /**
     * Constructor.
     *
     * @param publicKey     Public key used for encrypting.
     * @param privateKey    Private key used for decrypting.
     * @param signingSecret Secret used for signing
     */
    public AttributeConsentHistorySerializer(
            PublicKey publicKey,
            PrivateKey privateKey,
            String signingSecret) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.signingSecret = signingSecret;
        this.jwtBuilderFactory = new JwtBuilderFactory();
    }

    /**
     * Serialize and encrypt given history.
     *
     * @param history <code>AttributeConsentHistory</code> instance.
     * @return Encrypted jwt String.
     * @throws JsonProcessingException If unable to serialize history to JSON.
     */
    String serializeAndEncrypt(AttributeConsentHistory history) throws JsonProcessingException {
        String historyJson = mapper.writeValueAsString(history);

        JwtClaimsSet claimTobBeSigned = jwtBuilderFactory.claims().claim(JSON_KEY_HISTORY, historyJson).build();
        SignedJwt signedJwt = jwtBuilderFactory
                .jws(getSigningHandler(signingSecret))
                .headers()
                .alg(getSigningAlgorithm())
                .done()
                .claims(claimTobBeSigned)
                .asJwt();

        JwtClaimsSet claimToBeEncrypted = jwtBuilderFactory.claims().claim(JSON_KEY_SIGNED, signedJwt.build()).build();
        EncryptedJwt encryptedJwt = jwtBuilderFactory
                .jwe(publicKey)
                .headers()
                .alg(JweAlgorithm.RSAES_PKCS1_V1_5)
                .enc(EncryptionMethod.A128CBC_HS256)
                .done()
                .claims(claimToBeEncrypted)
                .asJwt();
        return encryptedJwt.build();
    }

    /**
     * Decrypt and deserialize encrypted jwt String.
     *
     * @param encryptedStr Encrypted jwt String
     * @return Deserialized <code>ConsentHistory</code> instance. Returns empty
     *         history if unable to deserialize or decrypt jwt.
     * @throws JsonProcessingException If unable to serialize history to JSON.
     */
    AttributeConsentHistory decryptAndDeserialize(String encryptedStr) {
        if (encryptedStr == null) {
            return new AttributeConsentHistory();
        }
        try {
            EncryptedJwt encryptedJwt = jwtBuilderFactory.reconstruct(encryptedStr, EncryptedJwt.class);
            encryptedJwt.decrypt(privateKey);

            String signedStr = encryptedJwt.getClaimsSet().getClaim(JSON_KEY_SIGNED, String.class);
            SignedJwt signedJwt = jwtBuilderFactory.reconstruct(signedStr, SignedJwt.class);

            if (!signedJwt.verify(getSigningHandler(signingSecret))) {
                DEBUG.message("Invalid signature.");
                return new AttributeConsentHistory();
            }
            String json = signedJwt.getClaimsSet().getClaim(JSON_KEY_HISTORY, String.class);
            DEBUG.message("Decrypted history: {}", json);
            return mapper.readValue(json, AttributeConsentHistory.class);
        } catch (InvalidJwtException e) {
            DEBUG.error("Invalid jwt was set in the request.", e);
            return new AttributeConsentHistory();
        } catch (JweDecryptionException e) {
            DEBUG.error("Unable to decrypt jwt.", e);
            return new AttributeConsentHistory();
        } catch (JsonProcessingException e) {
            DEBUG.error("Unable to deserialize history from json", e);
            return new AttributeConsentHistory();
        }
    }

    private SigningHandler getSigningHandler(String signingSecret) {
        SigningManager signingManager = new SigningManager();
        byte[] secretBytes = signingSecret.getBytes(Charset.forName("UTF-8"));
        return signingManager.newHmacSigningHandler(secretBytes);
    }

    private JwsAlgorithm getSigningAlgorithm() {
        return JwsAlgorithm.HS256;
    }

}
