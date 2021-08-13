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
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * Provide a way to handle server resident key cryptography.
 * 
 * Also provides static RNG and scratch services.
 */
public class ServerKeyCrypto {
    private static AESKey serverResidentKp;
    private static Cipher serverResidentEnc;
    private static Cipher serverResidentDec;
    private static RandomData rng;
    private static byte[] internalScratch;
    private static byte[] credScratch;

    public static void initKey() {
        if (rng == null) {
            rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
        try {
            internalScratch = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            internalScratch = new byte[32];
        }
        try {
            credScratch = JCSystem.makeTransientByteArray((short) 270, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            credScratch = new byte[270];
        }
        serverResidentKp = (AESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        rng.generateData(internalScratch, (short) 0, (short) 32);
        serverResidentKp.setKey(internalScratch, (short) 0);
        rng.generateData(internalScratch, (short) 0, (short) 32);
        serverResidentEnc = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        serverResidentEnc.init(serverResidentKp, Cipher.MODE_ENCRYPT);
        serverResidentDec = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        serverResidentDec.init(serverResidentKp, Cipher.MODE_DECRYPT);

    }

    public static RandomData getRng() {
        if (rng == null) {
            rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
        return rng;
    }

    public static byte[] getCredScratch() {
        return credScratch;
    }

    /**
     * Perform data encryption using the non-resident cryptographic key. Produces
     * output 16 bytes bigger than input. IV is prepended to the ciphertext.
     * 
     * @param inBuf
     * @param inOff
     * @param inLen
     * @param outBuf
     * @param outOff
     * @return
     */
    public static short encryptData(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // Generate an IV
        rng.generateData(internalScratch, (short) 0, (short) 16);
        // Re-initialise the Cipher
        serverResidentEnc.init(serverResidentKp, Cipher.MODE_ENCRYPT, internalScratch, (short) 0, (short) 16);
        Util.arrayCopy(internalScratch, (short) 0, outBuf, outOff, (short) 16);
        return (short) (16 + serverResidentEnc.doFinal(inBuf, inOff, inLen, outBuf, (short) (outOff + 16)));
    }

    /**
     * Perform data decryption using the non-resident cryptographic key. Produces
     * output 16 bytes shorter than input. IV is expected to be the first 16 bytes.
     * 
     * @param inBuf
     * @param inOff
     * @param inLen
     * @param outBuf
     * @param outOff
     * @return
     */
    public static short decryptData(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // Re-initialise the Cipher with the IV
        serverResidentDec.init(serverResidentKp, Cipher.MODE_DECRYPT, inBuf, inOff, (short) 16);
        // Actually decrypt the data
        return serverResidentDec.doFinal(inBuf, (short) (inOff + 16), (short) (inLen - 16), outBuf, outOff);
    }
}
