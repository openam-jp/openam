package jp.co.osstech.openam.authentication.modules.webauthn;

public class CredentialsCreateOptions {
    private String rpNameConfig;
    private String credentialIdBytesArrayStr; // byte[]
    private String userName;
    private String displayName;
    private String attestationConfig;
    private String attachmentConfig;
    private String residentKeyConfig;
    private String userVerificationConfig;
    private String challengeBytesArrayStr; // byte[]

    CredentialsCreateOptions() {

    }

    CredentialsCreateOptions(String rpNameConfig, byte[] credentialIdBytesArray, // byte[]
            String userName, String displayName, String attestationConfig, String attachmentConfig,
            String residentKeyConfig, String userVerificationConfig, byte[] challengeBytesArray // byte[]
    ) {
        this.rpNameConfig = rpNameConfig;
        this.credentialIdBytesArrayStr = convBytesArrayToStr(credentialIdBytesArray);
        this.userName = userName;
        this.displayName = displayName;
        this.attestationConfig = attestationConfig;
        this.attachmentConfig = attachmentConfig;
        this.residentKeyConfig = residentKeyConfig;
        this.userVerificationConfig = userVerificationConfig;
        this.challengeBytesArrayStr = convBytesArrayToStr(challengeBytesArray);

    }

    public String getRpNameConfig() {
        return rpNameConfig;
    }

    public void setRpNameConfig(String rpNameConfig) {
        this.rpNameConfig = rpNameConfig;
    }

    public String getCredentialIdBytesArrayStr() {
        return credentialIdBytesArrayStr;
    }

    public void setCredentialIdBytesArrayStr(String credentialIdBytesArrayStr) {
        this.credentialIdBytesArrayStr = credentialIdBytesArrayStr;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getAttachmentConfig() {
        return attachmentConfig;
    }

    public void setAttachmentConfig(String attachmentConfig) {
        this.attachmentConfig = attachmentConfig;
    }

    public String getAttestationConfig() {
        return attestationConfig;
    }

    public void setAttestationConfig(String attestationConfig) {
        this.attestationConfig = attestationConfig;
    }

    public String getResidentKeyConfig() {
        return residentKeyConfig;
    }

    public void setResidentKeyConfig(String residentKeyConfig) {
        this.residentKeyConfig = residentKeyConfig;
    }

    public String getUserVerificationConfig() {
        return userVerificationConfig;
    }

    public void setUserVerificationConfig(String userVerificationConfig) {
        this.userVerificationConfig = userVerificationConfig;
    }

    public String getChallengeBytesArrayStr() {
        return challengeBytesArrayStr;
    }

    public void setChallengeBytesArrayStr(String challengeBytesArrayStr) {
        this.challengeBytesArrayStr = challengeBytesArrayStr;
    }

    /*
     * generate secure random byte[]
     * 
     * @param int length
     * 
     * @return StringBuilder "," separated array String.
     */
    private String convBytesArrayToStr(byte[] byteArray) {

        StringBuilder BytesArrayStr = new StringBuilder();

        for (int i = 0; i < byteArray.length; i++) {
            BytesArrayStr.append(Byte.toUnsignedInt(byteArray[i])).append(",");
        }
        return BytesArrayStr.toString();
    }

}
