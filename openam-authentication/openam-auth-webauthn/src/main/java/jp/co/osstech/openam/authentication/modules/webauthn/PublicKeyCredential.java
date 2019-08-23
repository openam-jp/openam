package jp.co.osstech.openam.authentication.modules.webauthn;

public class PublicKeyCredential {
	
	/*
	 * for prototype only
	 * todo change private
	 * write get value code in this class
	 */
	private String id;
	private String rawId;
	private String type;
	private String attestationObject;
	private String clientDataJSON;
	private String authenticatorData;
	private String userHandle;
	private String signature;
	
	PublicKeyCredential(){
		
	}
	
	public String getId() {
		return id;
	}
	
	public String getRawId() {
		return rawId;
	}
	
	public String getType() {
		return type;
	}
	
	public String getAttestationObject() {
		return attestationObject;
	}
	
	public String getClientDataJSON() {
		return clientDataJSON;
	}
	
	public String getUserHandle() {
		return userHandle;
	}
	
	public String getSignature() {
		return signature;
	}
	
	public String getAuthenticatorData() {
		return authenticatorData;
	}
	
}
