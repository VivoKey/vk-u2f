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

import javacard.framework.JCSystem;
import javacard.framework.Util;
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
    public short performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // Performs the signature as per ES256 
        incrementCounter();
        return sig.sign(inBuf, inOff, inLen, outBuf, outOff);
        
    }
    @Override

    public short getAttestedData(byte[] buf, short off) {
        CBOREncoder enc = new CBOREncoder();
        // Get the ECPublicKey
        byte[] w = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
        ((ECPublicKey) kp.getPublic()).getW(w, (short) 0);
        // Form the pubkey and co
        // AAGUID
        Util.arrayCopy(CTAP2.aaguid, (short) 0, buf, off, (short) 16);
        // Length of the credential ID - 16 bytes
        short len = 16;
        buf[(short) (off+len++)] = 0x00;
        buf[(short) (off+len++)] = 0x10;
        // Copy the credential ID
        Util.arrayCopy(id, (short) 0, buf, (short) (off+len), (short) 16);
        len += 16;
        enc.init(buf, (short) (off + len), (short) 1000);
        enc.startMap((short) 5);
        len++;
        // We had to kinda hack the map labels - this is kty
        len += enc.writeRawByte((byte) 0x01);
        // EC2 keytype
        len += enc.encodeUInt8((byte) 0x02);
        // Alg - ES256
        len += enc.writeRawByte((byte) 0x03);
        len += enc.encodeNegativeUInt8((byte) 0x06);
        // Curve type - P256
        len += enc.writeRawByte((byte) -1);
        len += enc.encodeUInt8((byte) 0x01);
        // X coord
        len += enc.writeRawByte((byte) -2);
        len += enc.encodeByteString(w, (short) 1, (short) 32);
        // Y coord
        len += enc.writeRawByte((byte) -3);
        len += enc.encodeByteString(w, (short) 33, (short) 32);
        // That is all
        w = null;
        JCSystem.requestObjectDeletion();
        return len;
    }


    
}
