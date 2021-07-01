package com.vivokey.u2f.CTAPObjects;

public class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
    DomString rpId;
    
    public void setRp(byte[] pkId, short len) {
        rpId = new DomString(pkId, len);
    }
    /**
     * Checks the RP ID against the internal DomString.
     * @param inBuf
     * @param inOff
     * @param inLen
     * @return
     */
    public boolean checkId(byte[] inBuf, short inOff, short inLen) {
        return rpId.checkEquals(inBuf, inOff, inLen);
    }
}
