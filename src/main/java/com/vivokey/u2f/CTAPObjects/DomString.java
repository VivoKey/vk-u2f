package com.vivokey.u2f.CTAPObjects;

import javacard.framework.Util;

// Performs a very simple truncation
public class DomString {
    byte[] name;
    short len;
    // We limit name to length of 64 bytes or less. Errors are allowed, as the User Agent is responsible for managing invalid Unicode.
    public DomString(byte[] input, short len) {
        if(len > (short) 64) {
            len = 64;
        }
        name = new byte[len];
        Util.arrayCopy(input, (short) 0, name, (short) 0, len);
    }
}
