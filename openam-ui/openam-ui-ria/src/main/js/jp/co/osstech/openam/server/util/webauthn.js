/**
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

define("jp/co/osstech/openam/server/util/webauthn", [
    "jquery"
], function ($) {

    var obj = {};

    obj.createCredential = function (options) {
        $("#idToken3_0").hide();

        navigator.credentials.create(options)
            .then((Credential) => {
                const attestationObject = new Uint8Array(Credential.response.attestationObject);
                const clientDataJSON = new Uint8Array(Credential.response.clientDataJSON);
                const rawId = new Uint8Array(Credential.rawId);

                const jdata = {
                    id: Credential.id,
                    rawId: btoa(String.fromCharCode.apply(null, rawId)),
                    type: Credential.type,
                    attestationObject: btoa(String.fromCharCode.apply(null, attestationObject)),
                    clientDataJSON: btoa(String.fromCharCode.apply(null, clientDataJSON))
                };

                const jsonbody = JSON.stringify(jdata);
                console.log("NEW CREDENTIAL", Credential);
                console.log("Json data", jsonbody);
                $("#PublicKeyCredential").val(jsonbody);
                $("#idToken3_0").click();
            })
            .catch((err) => {
                console.log("ERROR", err);
            });
    };

    obj.getCredential = function (options) {
        $("#idToken3_0").hide();

        navigator.credentials.get(options)
            .then((Credential) => {
                const clientDataJSON = new Uint8Array(Credential.response.clientDataJSON);
                const signature = new Uint8Array(Credential.response.signature);
                const authenticatorData = new Uint8Array(Credential.response.authenticatorData);
                const rawId = new Uint8Array(Credential.rawId);
                const userHandle = new Uint8Array(Credential.response.userHandle);

                const jdata = {
                    id: Credential.id,
                    type: Credential.type,
                    rawId: btoa(String.fromCharCode.apply(null, rawId)),
                    userHandle: btoa(String.fromCharCode.apply(null, userHandle)),
                    authenticatorData: btoa(String.fromCharCode.apply(null, authenticatorData)),
                    signature: btoa(String.fromCharCode.apply(null, signature)),
                    clientDataJSON: btoa(String.fromCharCode.apply(null, clientDataJSON))
                };

                const jsonbody = JSON.stringify(jdata);
                console.log("Assersion", Credential);
                console.log("Json data", jsonbody);
                $("#PublicKeyCredential").val(jsonbody);
                $("#idToken3_0").click();
            })
            .catch((err) => {
                console.log("ERROR", err);
            });
    };

    return obj;
});
