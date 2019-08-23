define("jp/co/osstech/openam/server/util/webauthn", [
	"jquery"
],	function ($) {
	
	var obj = {};
	
	obj.createCredential = function (options){
		$('#idToken4_0').hide();
		navigator.credentials.create(options)
		
		.then((Credential) => {
			
			let attestationObject = new Uint8Array(Credential.response.attestationObject);
			let clientDataJSON = new Uint8Array(Credential.response.clientDataJSON);
			let rawId = new Uint8Array(Credential.rawId);
			
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
			$('#PublicKeyCredential').val(jsonbody);
			$('#idToken4_0').click();

		})
	    
		.catch((err) => {
			console.log("ERROR", err);
		});
	};
	
	obj.getCredential = function (options){
		$('#idToken4_0').hide();
		navigator.credentials.get(options)
		
		.then((Credential) => {
			
			let clientDataJSON = new Uint8Array(Credential.response.clientDataJSON);
			let signature = new Uint8Array(Credential.response.signature);
			let authenticatorData = new Uint8Array(Credential.response.authenticatorData);
			let rawId = new Uint8Array(Credential.rawId);
			let userHandle = new Uint8Array(Credential.response.userHandle);
			
			const jdata = {
					id: Credential.id,
					rawId: btoa(String.fromCharCode.apply(null, rawId)),
					userHandle: btoa(String.fromCharCode.apply(null, userHandle)),
					authenticatorData: btoa(String.fromCharCode.apply(null, authenticatorData)),
					signature: btoa(String.fromCharCode.apply(null, signature)),
					clientDataJSON: btoa(String.fromCharCode.apply(null, clientDataJSON))
			};

			const jsonbody = JSON.stringify(jdata);
			
			console.log("Assersion", Credential);
			console.log("Json data", jsonbody);
			$('#PublicKeyCredential').val(jsonbody);
			$('#idToken4_0').click();


		})
			
		.catch((err) => {
			console.log("ERROR", err);
		});
		
	};

	return obj;
	
});