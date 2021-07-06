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

import com.vivokey.u2f.CTAPObjects.PublicKeyCredentialRpEntity;
import com.vivokey.u2f.CTAPObjects.PublicKeyCredentialUserEntity;

import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.RandomData;

// Abstract class to represent and perform actions with a stored credential
public abstract class StoredCredential {
    private static RandomData rng = RandomData.getInstance(RandomData.ALG_TRNG);
    byte[] id;
    KeyPair kp;
    PublicKeyCredentialUserEntity user;
    PublicKeyCredentialRpEntity rp;
    protected StoredCredential() {
        id = new byte[16];
        rng.nextBytes(id, (short) 0, (short) 16);
    }
    // Generic ID check function, for credential IDs
    public boolean checkId(byte[] inBuf, short inOff, short inLen) {
        if(inLen != (short) 16) {
            return false;
        }
        return Util.arrayCompare(id, (short) 0, inBuf, inOff, inLen) == 0;
    }


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
