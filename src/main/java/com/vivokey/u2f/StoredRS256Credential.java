/*
**
** Copyright 2021, VivoKey Technologies
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/
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
        incrementCounter();
        // Increment sig counter first
        kpSignature.doFinal(inBuf, inOff, inLen, outBuf, outOff);
        
        
    }
    @Override
    public void getAttestedData(byte[] buf, short off) {
        // TODO Auto-generated method stub
        
    }
    
}
