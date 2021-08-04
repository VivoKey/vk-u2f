package com.vivokey.u2f;

import javacard.framework.Util;

public class PublicKeyCredentialDescriptor {
    byte[] type;
    byte[] id;
    public PublicKeyCredentialDescriptor(byte[] pkId, short offset, short len) {
        type = new byte[(short) (Utf8Strings.UTF8_PUBLIC_KEY.length)];
        Util.arrayCopy(Utf8Strings.UTF8_PUBLIC_KEY, (short) 0, type, (short) 0, (short) type.length);
        id = new byte[len];
        Util.arrayCopy(pkId, offset, id, (short) 0, (short) id.length);
    }
}
