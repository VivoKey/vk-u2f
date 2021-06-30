package com.vivokey.u2f.CTAPObjects;

public class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
    DomString rpId;
    
    public void setRp(byte[] pkId, short len) {
        rpId = new DomString(pkId, len);
    }
}
