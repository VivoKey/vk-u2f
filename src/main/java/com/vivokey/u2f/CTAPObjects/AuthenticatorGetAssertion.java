package com.vivokey.u2f.CTAPObjects;

import com.vivokey.u2f.CBORDecoder;

import javacard.framework.JCSystem;

public class AuthenticatorGetAssertion {
    byte[] rpId;
    byte[] clientDataHash;
    PublicKeyCredentialDescriptor[] allowList;
    boolean[] options;

    public AuthenticatorGetAssertion(CBORDecoder decoder, short[] vars) {
        // Read ID 1 in
        decoder.readInt8();
        // Read the byte string in
        byte[] scratch;
        try {
            scratch = JCSystem.makeTransientByteArray((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        } catch (Exception e) {
            scratch = new byte[64];
        }
        // Create the rpId storage
        vars[0] = decoder.readByteString(scratch, (short) 0);
        rpId = new byte[vars[0]];
        // Copy to it
        System.arraycopy(scratch, (short) 0, rpId, (short) 0, vars[0]);
        // Do the same with the clientDataHash
        decoder.readInt8();
        decoder.readByteString(scratch, (short) 0);
        clientDataHash = new byte[16];
        System.arraycopy(scratch, (short) 0, clientDataHash, (short) 0, (short) 16);
        // TODO: finish
    }
}
