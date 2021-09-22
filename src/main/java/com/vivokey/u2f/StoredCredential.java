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
import javacard.framework.UserException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.HMACKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

// Abstract class to represent and perform actions with a stored credential
public abstract class StoredCredential {
    private static RandomData rng;
    byte[] id;
    KeyPair kp;
    PublicKeyCredentialUserEntity user;
    PublicKeyCredentialRpEntity rp;
    private byte[] sigCounter;
    protected boolean initialised;

    protected byte[] credRandom;
    protected boolean hmacEnabled;
    protected Signature hmacSig;
    protected Signature credSig;
    protected AESKey credAES;
    protected HMACKey credHMAC;
    protected byte[] out1;
    protected byte[] out2;

    protected static Signature hmacSigShared;
    protected static HMACKey secretShared;
    protected static Cipher sharedAes;
    protected static AESKey sharedAesKey;

    protected StoredCredential() {
        if (rng == null) {
            rng = ServerKeyCrypto.getRng();
            hmacSigShared = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_HMAC, Cipher.PAD_NULL,
                    false);
            secretShared = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_RESET,
                    KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
            sharedAesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256,
                    false);
            sharedAes = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        }
        id = new byte[16];
        rng.generateData(id, (short) 0, (short) 16);
        sigCounter = new byte[4];
        initialised = false;
        hmacEnabled = false;

    }

    // Does the HMAC secret stuff
    public short doHmacSecret(HMACSecret hmacSec, KeyAgreement ecKeyAg, MessageDigest sha, byte[] out, short outOff)
            throws UserException {
        byte[] scratch;
        try {
            scratch = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            scratch = new byte[32];
        }
        // First off, finalise the ecKeyAg as it's got a private key loaded
        ecKeyAg.generateSecret(hmacSec.w, (short) 0, (short) 65, scratch, (short) 0);
        // Actually hash the x co-ordinate
        byte[] sharedSec = new byte[32];
        sha.doFinal(scratch, (short) 0, (short) 32, sharedSec, (short) 0);

        // This is the shared secret
        secretShared.setKey(sharedSec, (short) 0, (short) 32);
        // Generate a HMAC thing
        hmacSigShared.init(secretShared, Signature.MODE_SIGN);
        // Check the saltEnc by hashing that and verifying the first 16 bytes match auth
        hmacSigShared.sign(hmacSec.encSalts, (short) 0, (short) (hmacSec.encSalts.length - (short) 1), scratch,
                (short) 0);
        if (Util.arrayCompare(hmacSec.auth, (short) 0, scratch, (short) 0, (short) 16) != 0) {
            // Problem
            UserException.throwIt(CTAP2.CTAP2_ERR_NOT_ALLOWED);
            return 0;
        }
        // Must match - our shared secret is all good

        // Init the AES decryption key
        sharedAesKey.setKey(sharedSec, (short) 0);
        // Init the decryptor
        sharedAes.init(sharedAesKey, Cipher.MODE_DECRYPT);
        // Decrypt the salts
        byte[] salts = new byte[hmacSec.encSalts.length];
        sharedAes.doFinal(hmacSec.encSalts, (short) 0, (short) (hmacSec.encSalts.length), salts, (short) 0);
        // Init the hmac thing
        hmacSig.init(credHMAC, Signature.MODE_SIGN);
        // Sign first salt
        hmacSig.sign(salts, (short) 0, (short) 32, out1, (short) 0);
        // Re-use sharedAes in encrypt mode
        sharedAes.init(sharedAesKey, Cipher.MODE_ENCRYPT);
        // Check if there's one or two salts
        if ((short) (salts.length) == (short) 32) {
            // One salt
            // Do the output stuff (re-encrypt with the shared secret)
            return sharedAes.doFinal(out1, (short) 0, (short) 32, out, outOff);
        } else {
            // Two salts
            // Do the second salt
            hmacSig.sign(salts, (short) 32, (short) 32, out2, (short) 0);
            byte[] outs = new byte[64];
            Util.arrayCopy(out1, (short) 0, outs, (short) 0, (short) 32);
            Util.arrayCopy(out2, (short) 0, outs, (short) 32, (short) 32);
            return sharedAes.doFinal(outs, (short) 0, (short) 64, out, outOff);
        }

    }

    // Initialise the credRandom
    public boolean initialiseCredSecret() {
        // Generate the actual credRandom
        credRandom = new byte[32];
        rng.generateData(credRandom, (short) 0, (short) 32);
        hmacEnabled = true;
        // Set up the keys and crypto bits 
        credAES = (AESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        credHMAC = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
        credAES.setKey(credRandom, (short) 0);
        hmacSig = Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_HMAC, Cipher.PAD_NULL,
        false);
        // Some memory to generate out1 and out2
        out1 = new byte[32];
        out2 = new byte[32];
        return true;
    }

    // Generic ID check function, for credential IDs
    public boolean checkId(byte[] inBuf, short inOff, short inLen) {
        if (inLen != (short) 16) {
            return false;
        }
        return Util.arrayCompare(id, (short) 0, inBuf, inOff, inLen) == 0;
    }

    public boolean[] getPresentUser() {
        return user.dataPresent;
    }

    /**
     * Increment the counter. NOTE: Atomic.
     */
    protected void incrementCounter() {
        JCSystem.beginTransaction();

        for (short i = 3; i > 1; i--) {
            if (sigCounter[i] == 0xFF) {
                sigCounter[(short) (i - 1)]++;
                sigCounter[i] = 0x00;
                JCSystem.commitTransaction();
                return;
            }
        }
        if (sigCounter[0] == 0xFF && sigCounter[1] == 0xFF && sigCounter[2] == 0xFF && sigCounter[3] == 0xFF) {
            // Overflow, roll to 0
            Util.arrayFillNonAtomic(sigCounter, (short) 0, (short) 4, (byte) 0x00);
            JCSystem.commitTransaction();
            return;
        }
        sigCounter[3]++;
        JCSystem.commitTransaction();
    }

    /**
     * Copies the counter (a 32-bit unsigned int) to the buffer specified, at offset
     * bufOff.
     * 
     * @param buf    the buffer to copy into
     * @param bufOff the offset to begin at
     * @returns length
     */
    public short readCounter(byte[] buf, short bufOff) {
        Util.arrayCopy(sigCounter, (short) 0, buf, bufOff, (short) 4);
        return (short) 4;
    }

    /**
     * Signature class. Signs into the output buffer from the input buffer using the
     * keypair.
     * 
     * @param inBuf  input buffer to sign
     * @param inOff  offset in buffer
     * @param inLen  length of data to sign
     * @param outBuf output buffer to sign into
     * @param outOff output buffer offset to begin writing at
     */
    public abstract short performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff);

    /**
     * Returns the attestation data (pubkey and definition) attached to this object.
     * 
     * @param buf buffer to copy the details to
     * @param off offset to begin copying to
     * @returns length
     */
    public abstract short getAttestedData(byte[] buf, short off);

    /**
     * Returns the length of the attestation data that will be fed later on.
     * 
     * @returns length
     */
    public abstract short getAttestedLen();

    /**
     * Protected common attestation parameters
     * 
     * @param buf
     * @param off
     * @return
     */
    protected void doAttestationCommon(byte[] buf, short off) {
        // AAGUID
        Util.arrayCopy(CTAP2.aaguid, (short) 0, buf, off, (short) 16);
        // Length of the credential ID - 16 bytes
        buf[(short) (off + 16)] = 0x00;
        buf[(short) (off + 17)] = 0x10;
        // Copy the credential ID
        Util.arrayCopy(id, (short) 0, buf, (short) (off + 18), (short) 16);

    }
}
