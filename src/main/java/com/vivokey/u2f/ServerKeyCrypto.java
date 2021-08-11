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
