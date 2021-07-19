package com.vivokey.u2f.CTAPObjects;

import javacard.framework.Util;

public class PublicKeyCredentialDescriptor {
    private byte[] id;
    private static final byte[] type = {'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'};
    public PublicKeyCredentialDescriptor(byte[] id, short off, short len) {
        this.id = new byte[len];
        Util.arrayCopy(id, off, this.id, (short) 0, len);
        // TODO: Finish
    }

}
