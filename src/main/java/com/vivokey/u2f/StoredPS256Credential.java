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

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

public class StoredPS256Credential extends StoredCredential {
    Signature kpSignature;
    public StoredPS256Credential(AuthenticatorMakeCredential inputData) {
        // Generate a new RS256 credential
        kp = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
        kp.genKeyPair();
        // Generate a signature object
        kpSignature = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1_PSS, false);
        kpSignature.init(kp.getPrivate(), Signature.MODE_SIGN);
        user = inputData.getUser();
        rp = inputData.getRp();
    }
    @Override
    public void performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        incrementCounter();
        // Increment sig counter first
        kpSignature.sign(inBuf, inOff, inLen, outBuf, outOff);
        
        
    }
    @Override
    public void getAttestedData(byte[] buf, short off) {
        CBOREncoder enc = new CBOREncoder();
        // Get the RSAPublicKey
        byte[] mod = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
        byte[] exp = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_RESET);
        ((RSAPublicKey) kp.getPublic()).getModulus(mod, (short) 0);
        ((RSAPublicKey) kp.getPublic()).getExponent(exp, (short) 0);
        // AAGUID
        Util.arrayCopy(CTAP2.aaguid, (short) 0, buf, off, (short) 16);
        // Length of the credential ID - 16 bytes
        buf[off+16] = 0x00;
        buf[off+17] = 0x10;
        // Copy the credential ID
        Util.arrayCopy(id, (short) 0, buf, (short) (off+18), (short) 16);
        // Start the public key CBOR
        enc.init(buf, (short) (off + 34), (short) 1000);
        enc.startMap((short) 5);
        // kty - key type
        enc.writeRawByte((byte) 0x01);
        // RSA
        enc.encodeUInt8((byte) 0x03);
        // alg
        enc.writeRawByte((byte) 0x03);
        // PS256 - -37 is 36 negative (minus 1 for neg on CBOR)
        enc.encodeNegativeUInt8((byte) 36);
        // Modulus tag
        enc.writeRawByte((byte) -1);
        // Write the modulus
        enc.encodeByteString(mod, (short) 0, (short) 256);
        // Exponent tag
        enc.writeRawByte((byte) -2);
        // Write the exponent
        enc.encodeByteString(exp, (short) 0, (short) 3);
    }
    
}
