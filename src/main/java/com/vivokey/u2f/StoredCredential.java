package com.vivokey.u2f;

import com.vivokey.u2f.CTAPObjects.PublicKeyCredentialRpEntity;
import com.vivokey.u2f.CTAPObjects.PublicKeyCredentialUserEntity;

import javacard.security.KeyPair;

// Abstract class to represent and perform actions with a stored credential
public abstract class StoredCredential {
    KeyPair kp;
    PublicKeyCredentialUserEntity user;
    PublicKeyCredentialRpEntity rp;
    /**
     * Signature class. Signs into the output buffer from the input buffer using the keypair. 
     * @param inBuf input buffer to sign
     * @param inOff offset in buffer
     * @param inLen length of data to sign
     * @param outBuf output buffer to sign into
     * @param outOff output buffer offset to begin writing at
     */
    public abstract void performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff);
    /**
     * Returns the public key attached to this object.
     * @param outBuf buffer to copy the key into
     * @param outOff offset to begin copying to
     */
    public abstract void getPublic(byte[] outBuf, short outOff);
}
