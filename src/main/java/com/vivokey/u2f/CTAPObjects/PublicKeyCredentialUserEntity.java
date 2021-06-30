package com.vivokey.u2f.CTAPObjects;

import javacard.framework.Util;

public class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
    byte[] id;
    DomString displayName;
    
    public void setId(byte[] src, short len) {
        id = new byte[len];
        Util.arrayCopy(src, (short) 0, id, (short) 0, len);
    }
    public void setDisplayName(byte[] src, short len) {
        displayName = new DomString(src, len);
    }

}
