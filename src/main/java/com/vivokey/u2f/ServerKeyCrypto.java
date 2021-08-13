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

import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * Provide a way to handle server resident key cryptography.
 * 
 * Also provides static RNG
 */
public class ServerKeyCrypto {
    private static AESKey serverResidentKp;
    private static Cipher serverResidentEnc;
    private static Cipher serverResidentDec;
    private static RandomData rng;
    
    public static void initKey() {
        if(rng == null) {
            rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
        byte[] scratch = new byte[32];
        serverResidentKp = (AESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        rng.generateData(scratch, (short) 0, (short) 32);
        serverResidentKp.setKey(scratch, (short) 0);
        rng.generateData(scratch, (short) 0, (short) 32);
        serverResidentEnc = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        serverResidentEnc.init(serverResidentKp, Cipher.MODE_ENCRYPT);
        serverResidentDec = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        serverResidentDec.init(serverResidentKp, Cipher.MODE_DECRYPT);
    } 

    public static RandomData getRng() {
        if(rng == null) {
            rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
        return rng;
    }

    public static short encryptData(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        return serverResidentEnc.doFinal(inBuf, inOff, inLen, outBuf, outOff);
    }
    public static short decryptData(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        return serverResidentDec.doFinal(inBuf, inOff, inLen, outBuf, outOff);
    }
}
