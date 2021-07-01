package com.vivokey.u2f;

import com.vivokey.u2f.CTAPObjects.AuthenticatorMakeCredential;

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;

public class StoredRS256Credential extends StoredCredential {
    Cipher kpSignature;
    public StoredRS256Credential(AuthenticatorMakeCredential inputData) {
        // Generate a new RS256 credential
        kp = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
        kp.genKeyPair();
        // Generate a signature object
        kpSignature = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        kpSignature.init(kp.getPrivate(), Cipher.MODE_ENCRYPT);
        user = inputData.getUser();
        rp = inputData.getRp();
    }
    @Override
    public void performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // TODO Auto-generated method stub
        
    }
    @Override
    public void getPublic(byte[] outBuf, short outOff) {
        // TODO Auto-generated method stub
        
    }
    
}
