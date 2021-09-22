package com.vivokey.u2f;

import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.MessageDigest;

// Turns out, NXP don't implement HMAC on their cards
// So we implemented it ourselves
public class HMACSigner {
    private static MessageDigest sha;
    private byte[] rawKey;

    private static final byte ipad = 0x36;
    private static final byte opad = 0x5C;
    private static final short LEN_HMAC_BLOCK = (short) 64;
    private byte[] rndBuffer;
    private byte[] ipadK;
    private byte[] opadK;

    public HMACSigner() {
        if (sha == null) {
            sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        }
        try {
            rndBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            rndBuffer = new byte[32];
        }
        try {
            ipadK = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            ipadK = new byte[64];
        }
        try {
            opadK = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            opadK = new byte[64];
        }


    }

    /**
     * Initialises the HMACSigner with an AES key.
     * 
     * @param key the AES key to be used.
     */
    public void init(AESKey key) {
        rawKey = new byte[(short) (key.getSize() / 8)];
        key.getKey(rawKey, (short) 0);
    }

    /**
     * Performs a HMAC on the input data.
     * 
     * @param inBuf
     * @param inOff
     * @param inLen
     * @param outBuf
     * @param outOff
     */
    public short doFinal(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // Perform padding and xoring of the CredSecret key
        for (short i = 0; i < LEN_HMAC_BLOCK; i++) {
            // for each byte of the key, work out the pad byte
            if (i >= 32) {
                ipadK[i] = (byte) (0x00 ^ ipad);
                opadK[i] = (byte) (0x00 ^ opad);
            } else {
                ipadK[i] = (byte) (rawKey[i] ^ ipad);
                opadK[i] = (byte) (rawKey[i] ^ opad);
            }
        }
        sha.reset();
        sha.update(ipadK, (short) 0, LEN_HMAC_BLOCK);
        sha.doFinal(inBuf, inOff, inLen, rndBuffer, (short) 0);

        // now find H(opadK, rndBuffer)
        sha.reset();
        sha.update(opadK, (short) 0, LEN_HMAC_BLOCK);
        short outputLength;
        outputLength = sha.doFinal(rndBuffer, (short) 0, (short) 32, outBuf, outOff);
        sha.reset();

        return outputLength;

    }

}
