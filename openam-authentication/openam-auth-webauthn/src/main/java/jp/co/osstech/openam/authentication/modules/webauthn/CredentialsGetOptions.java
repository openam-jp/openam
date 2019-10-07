package jp.co.osstech.openam.authentication.modules.webauthn;

import java.util.Base64;

public class CredentialsGetOptions {
    private String credentialIdBytesArrayStr; // byte[]
    private String userVerificationConfig;
    private String challengeBytesArrayStr; // byte[]

    CredentialsGetOptions(String credentialIdBase64, String userVerificationConfig, byte[] challengeBytesArray // byte[]
    ) {
        this.setCredentialIdBytesArrayStr(convBytesArrayToStr(Base64.getDecoder().decode(credentialIdBase64)));
        this.setUserVerificationConfig(userVerificationConfig);
        this.setChallengeBytesArrayStr(convBytesArrayToStr(challengeBytesArray));

    }

    CredentialsGetOptions(byte[] credentialIdBytesArray, // byte[],
            String userVerificationConfig, byte[] challengeBytesArray // byte[]
    ) {
        this.setCredentialIdBytesArrayStr(convBytesArrayToStr(credentialIdBytesArray));
        this.setUserVerificationConfig(userVerificationConfig);
        this.setChallengeBytesArrayStr(convBytesArrayToStr(challengeBytesArray));

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

    public String getCredentialIdBytesArrayStr() {
        return credentialIdBytesArrayStr;
    }

    public void setCredentialIdBytesArrayStr(String credentialIdBytesArrayStr) {
        this.credentialIdBytesArrayStr = credentialIdBytesArrayStr;
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
}
