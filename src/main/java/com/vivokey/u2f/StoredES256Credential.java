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

import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class StoredES256Credential extends StoredCredential {

    Signature sig;
    public StoredES256Credential(AuthenticatorMakeCredential inputData) {
        // Generate a new ES256 credential
        kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        Secp256r1.setCommonCurveParameters((ECKey) kp.getPublic());
        kp.genKeyPair();
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sig.init(kp.getPublic(), Signature.MODE_SIGN);
        user = inputData.getUser();
        rp = inputData.getRp();
    }
    @Override
    public void performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // Performs the signature as per ES256 
        sig.sign(inBuf, inOff, inLen, outBuf, outOff);
        
    }

    @Override
    public void getPublic(byte[] outBuf, short outOff) {
        // Copy the public key into the output buffer
        ((ECPublicKey) kp.getPublic()).getW(outBuf, outOff);
        
    }
    
}
