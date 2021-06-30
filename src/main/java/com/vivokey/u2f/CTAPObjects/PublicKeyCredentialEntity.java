package com.vivokey.u2f.CTAPObjects;

// WebAuthn 5.4.1
public abstract class PublicKeyCredentialEntity {
    // DOMString name
    DomString name;

    public void setName(byte[] pkName, short len) {
        name = new DomString(pkName, len);
    }


}
