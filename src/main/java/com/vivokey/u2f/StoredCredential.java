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
import javacard.security.KeyPair;
import javacard.security.RandomData;

// Abstract class to represent and perform actions with a stored credential
public abstract class StoredCredential {
    private static RandomData rng;
    byte[] id;
    KeyPair kp;
    PublicKeyCredentialUserEntity user;
    PublicKeyCredentialRpEntity rp;
    private byte[] sigCounter;
    protected boolean initialised;
    protected StoredCredential() {
        if(rng == null) {
            rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
        id = new byte[16];
        rng.generateData(id, (short) 0, (short) 16);
        sigCounter = new byte[4];
        initialised = false;
    }
    // Generic ID check function, for credential IDs
    public boolean checkId(byte[] inBuf, short inOff, short inLen) {
        if(inLen != (short) 16) {
            return false;
        }
        return Util.arrayCompare(id, (short) 0, inBuf, inOff, inLen) == 0;
    }
    /**
     * Increment the counter.
     * NOTE: Atomic.
     */
    protected void incrementCounter() {
        JCSystem.beginTransaction();

        for(short i = 3; i > 1; i--) {
            if(sigCounter[i] == 0xFF) {
                sigCounter[(short) (i-1)]++;
                sigCounter[i] = 0x00;
                JCSystem.commitTransaction();
                return;
            }
        }
        if(sigCounter[0] == 0xFF && sigCounter[1] == 0xFF && sigCounter[2] == 0xFF && sigCounter[3] == 0xFF) {
            // Overflow, roll to 0
            Util.arrayFillNonAtomic(sigCounter, (short) 0, (short) 4, (byte) 0x00);
            JCSystem.commitTransaction();
            return;
        }
        sigCounter[3]++;
        JCSystem.commitTransaction();
    }
    /**
     * Copies the counter (a 32-bit unsigned int) to the buffer specified, at offset bufOff.
     * @param buf the buffer to copy into
     * @param bufOff the offset to begin at
     * @returns length
     */
    public short readCounter(byte[] buf, short bufOff) {
        Util.arrayCopy(sigCounter, (short) 0, buf, bufOff, (short) 4);
        return (short) 4;
    }


    /**
     * Signature class. Signs into the output buffer from the input buffer using the keypair. 
     * @param inBuf input buffer to sign
     * @param inOff offset in buffer
     * @param inLen length of data to sign
     * @param outBuf output buffer to sign into
     * @param outOff output buffer offset to begin writing at
     */
    public abstract short performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff);
    /**
     * Returns the attestation data (pubkey and definition) attached to this object.
     * @param buf buffer to copy the details to
     * @param off offset to begin copying to
     * @returns length
     */
    public abstract short getAttestedData(byte[] buf, short off);


    /**
     * Returns the length of the attestation data that will be fed later on.
     * @returns length
     */
    public abstract short getAttestedLen();

    /**
     * Protected common attestation parameters
     * @param buf
     * @param off
     * @return
     */
    protected void doAttestationCommon(byte[] buf, short off) {
        // AAGUID
        Util.arrayCopy(CTAP2.aaguid, (short) 0, buf, off, (short) 16);
        // Length of the credential ID - 16 bytes
        buf[(short) (off+16)] = 0x00;
        buf[(short) (off+17)] = 0x10;
        // Copy the credential ID
        Util.arrayCopy(id, (short) 0, buf, (short) (off+18), (short) 16);

    }
}
