/*
*******************************************************************************
*   FIDO U2F Authenticator
*   (c) 2015 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*******************************************************************************
*/

package com.vivokey.u2f;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.AESKey;
import javacardx.crypto.Cipher;
import javacard.framework.JCSystem;
import javacard.security.RandomData;
import javacard.framework.Util;

public class FIDOStandalone implements FIDOAPI {
    // Most U2F authenticators use a key handle length of
    // 64 bytes. While we could get away with using a 49 byte
    // handle, this would be a tell about what kind of
    // authenticator we were using. So to maintain privacy,
    // we use a 64-byte key handle just like almost everyone
    // else.
    private static final short KEY_HANDLE_LENGTH = 64;

    // Only used by generateKeyAndWrap().
    private KeyPair keyPair;

    private Cipher cipherEncrypt;
    private Cipher cipherDecrypt;
    private byte[] scratch;

    private static final byte[] IV_ZERO_AES = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    public FIDOStandalone() {
        scratch = JCSystem.makeTransientByteArray(KEY_HANDLE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        keyPair = new KeyPair(
            (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
            (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
        Secp256r1.setCommonCurveParameters((ECKey)keyPair.getPrivate());
        Secp256r1.setCommonCurveParameters((ECKey)keyPair.getPublic());
        RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        // Initialize the unique wrapping key
        AESKey chipKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        random.generateData(scratch, (short)0, (short)32);
        chipKey.setKey(scratch, (short)0);
        cipherEncrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipherEncrypt.init(chipKey, Cipher.MODE_ENCRYPT, IV_ZERO_AES, (short)0, (short)IV_ZERO_AES.length);
        cipherDecrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipherDecrypt.init(chipKey, Cipher.MODE_DECRYPT, IV_ZERO_AES, (short)0, (short)IV_ZERO_AES.length);
    }

    private static void interleave(byte[] array1, short array1Offset, byte[] array2, short array2Offset, byte[] target, short targetOffset, short length) {
        for (short i=0; i<length; i++) {
            short a = (short)(array1[(short)(array1Offset + i)] & 0xff);
            short b = (short)(array2[(short)(array2Offset + i)] & 0xff);
            target[(short)(targetOffset + 2 * i)] = (byte)((short)(a & 0xf0) | (short)(b >> 4));
            target[(short)(targetOffset + 2 * i + 1)] = (byte)((short)((a & 0x0f) << 4) | (short)(b & 0x0f));
        }
    }

    private static void deinterleave(byte[] src, short srcOffset, byte[] array1, short array1Offset, byte[] array2, short array2Offset, short length) {
        for (short i=0; i<length; i++) {
            short a = (short)(src[(short)(srcOffset + 2 * i)] & 0xff);
            short b = (short)(src[(short)(srcOffset + 2 * i + 1)] & 0xff);
            array1[(short)(array1Offset + i)] = (byte)((short)(a & 0xf0) | (short)(b >> 4));
            array2[(short)(array2Offset + i)] = (byte)(((short)(a & 0x0f) << 4) | (short)(b & 0x0f));
        }
    }

    public short generateKeyAndWrap(byte[] applicationParameter, short applicationParameterOffset, byte[] publicKey, short publicKeyOffset, byte[] keyHandle, short keyHandleOffset, byte info) {
        // Here we are using the cipherEncrypt object as
        // a way to calculate a CBC-MAC. In this case we
        // will be writing out the encrypted application
        // parameter to bytes 16 thru 47 of `scratch`.
        // However, we will only be using the last 16
        // bytes---the first 16 bytes will be overwritten
        // by the private key a few steps down.
        cipherEncrypt.doFinal(applicationParameter, applicationParameterOffset, (short)32, scratch, (short)16);

        // Put our "info" byte as the first byte after
        // our CBC-MAC of the application parameter.
        scratch[48] = info;

        // Fill bytes 49 through 63 with zeros.
        Util.arrayFillNonAtomic(scratch, (short)49, (short)15, (byte)0x00);

        // Generate a new key pair.
        keyPair.genKeyPair();

        // Copy public key out.
        ((ECPublicKey)keyPair.getPublic()).getW(publicKey, publicKeyOffset);

        // Write the private key to bytes 0-31 of
        // the scratch memory, overwriting the first
        // block of the application parameter we
        // encrypted above. This is OK because we
        // only care about the later 16 bytes, which
        // we will be using as a MAC.
        ((ECPrivateKey)keyPair.getPrivate()).getS(scratch, (short)0);

        // At this point the scratch looks like this:
        //
        // * bytes 0-31: Private key
        // * bytes 32-47: CBC-MAC(chipKey, applicationParameter)
        // * byte  48: "Info" byte
        // * Bytes 49-63: Zero padding

        // Take the upper and lower parts of scratch
        // memory and reversibly mix them together.
        interleave(scratch, (short)32, scratch, (short)0, keyHandle, keyHandleOffset, (short)32);

        // Encrypt the mixed buffer using the chipKey.
        cipherEncrypt.doFinal(keyHandle, keyHandleOffset, KEY_HANDLE_LENGTH, keyHandle, keyHandleOffset);

        // Zero out the bytes we used in scratch memory.
        Util.arrayFillNonAtomic(scratch, (short)0, (short)49, (byte)0x00);

        return KEY_HANDLE_LENGTH;
    }

    public byte unwrap(byte[] keyHandle, short keyHandleOffset, short keyHandleLength, byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey unwrappedPrivateKey) {
        // Fail early if the key handle length is obviously wrong.
        if (keyHandleLength != KEY_HANDLE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Decrypt the key handle in-place.
        cipherDecrypt.doFinal(keyHandle, keyHandleOffset, KEY_HANDLE_LENGTH, keyHandle, keyHandleOffset);

        // Reverse the mixing step that we performed in
        // generateKeyAndWrap.
        deinterleave(keyHandle, keyHandleOffset, scratch, (short)32, scratch, (short)0, (short)32);

        // At this point the scratch *should* look like this:
        //
        // * bytes 0-31: Private key
        // * bytes 32-47: CBC-MAC(chipKey, applicationParameter)
        // * byte  48: "Info" byte
        // * Bytes 49-63: Zero padding

        // Save our "info" byte for later.
        byte info = scratch[48];

        // In order to verify that this key handle is for this
        // application parameter, we need to calculate the CBC-MAC
        // of the application parameter so that we can compare it
        // to the CBC-MAC in the decrypted and unmixed key handle.
        // Here we encrypt the application parameter, but we will
        // be using only the last 16-bytes. We encrypt it into the
        // keyHandle buffer since we don't need it anymore.
        cipherEncrypt.doFinal(applicationParameter, applicationParameterOffset, (short)32, keyHandle, keyHandleOffset);

        // This is where we actually verify if this key handle
        // is for this application parameter on this device.
        // We don't need to do a constant-time comparison here
        // because we are comparing MAC values---so an attacker
        // cannot glean any actionable information from a timing
        // attack.
        if (0 != Util.arrayCompare(keyHandle, (short)(keyHandleOffset+16), scratch, (short)32, (short)16)) {
            // Clean up the buffers we used.
            Util.arrayFillNonAtomic(scratch, (short)0, (short)64, (byte)0x00);
            Util.arrayFillNonAtomic(keyHandle, keyHandleOffset, KEY_HANDLE_LENGTH, (byte)0x00);

            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (unwrappedPrivateKey != null) {
            unwrappedPrivateKey.setS(scratch, (short)0, (short)32);
        }

        // Clean up the buffers we used.
        Util.arrayFillNonAtomic(scratch, (short)0, (short)64, (byte)0x00);
        Util.arrayFillNonAtomic(keyHandle, keyHandleOffset, KEY_HANDLE_LENGTH, (byte)0x00);
        return info;
    }
}
