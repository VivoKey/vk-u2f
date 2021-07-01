package com.vivokey.u2f.CTAPObjects;

import javacard.framework.Util;

// Performs a very simple truncation
public class DomString {
    byte[] str;
    short len;
    // We limit name to length of 64 bytes or less. Errors are allowed, as the User Agent is responsible for managing invalid Unicode.
    public DomString(byte[] input, short len) {
        if(len > (short) 64) {
            len = 64;
        }
        str = new byte[len];
        Util.arrayCopy(input, (short) 0, str, (short) 0, len);
    }
    /**
     * Checks the equality of a DomString to an inputBuf. 
     * Performs truncation in the same manner as creation.
     * @param inputBuf
     * @param inOff
     * @param inLen
     * @return
     */
    public boolean checkEquals(byte[] inputBuf, short inOff, short inLen) {
        if(inLen > 64) {
            inLen = 64;
        }
        if(inLen != len) {
            return false;
        }
        return (Util.arrayCompare(inputBuf, inOff, str, (short) 0, len)==0);
    }
}
