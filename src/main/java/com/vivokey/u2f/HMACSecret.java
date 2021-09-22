package com.vivokey.u2f;

import javacard.framework.JCSystem;
import javacard.framework.UserException;
import javacard.framework.Util;

// Stores the key agreement and associated details of the hmac-secret extension
public class HMACSecret {

    public byte[] w;
    public byte[] encSalts;
    public byte[] auth;

    public HMACSecret(CBORDecoder dec) throws UserException {

        // Start decoding the hmac-secret part of this
        short len = dec.readMajorType(CBORBase.TYPE_MAP);
        for (short i = 0; i < len; i++) {
            switch (dec.readInt8()) {
                case 0x01:
                    // The COSE key for DH
                    // Another map
                    short coseLen = dec.readMajorType(CBORBase.TYPE_MAP);
                    if (coseLen != 5) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Initialise w to make the pubkey out of
                    try {
                        w = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
                    } catch (Exception e) {
                        w = new byte[65];
                    }
                    // First tag, 0x01
                    dec.readRawByte();
                    // Value should be 2
                    short val = dec.readInt8();
                    if (val != 2) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Second tag, 0x03
                    dec.readRawByte();

                    // There's a weird issue here
                    // It's a two-byte thing, but maybe shouldn't be, idk
                    val = dec.readInt8();
                    if (val != (short) 24) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Next tag, -1
                    dec.readRawByte();
                    // Crv, should be 1
                    val = dec.readInt8();
                    if (val != 1) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Next tag, -2
                    dec.readRawByte();
                    try {
                        dec.readByteString(w, (short) 1);
                    } catch (Exception e) {
                        UserException.throwIt((byte) 0x71);
                        break;
                    }
                    // Tag -3
                    dec.readRawByte();
                    try {
                        dec.readByteString(w, (short) 33);
                    } catch (Exception e) {
                        UserException.throwIt((byte) 0x72);
                        break;
                    }
                    break;
                case 0x02:
                    // This is some kind of salting thing
                    // Read it in
                    byte[] tmp = new byte[64];
                    short len2 = 0;
                    try {
                        len = dec.readByteString(tmp, (short) 0);
                    } catch (Exception e) {
                        UserException.throwIt((byte) 0x73);
                        break;
                    }
                    if (len2 == 32) {
                        encSalts = new byte[32];
                        Util.arrayCopy(tmp, (short) 0, encSalts, (short) 0, (short) 32);
                    } else if (len2 == 64) {
                        encSalts = new byte[64];
                        Util.arrayCopy(tmp, (short) 0, encSalts, (short) 0, (short) 64);
                    } else {
                        UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_OPTION);
                    }
                    break;
                case 0x03:
                    // Some kind of authentication
                    // Read it in
                    auth = new byte[16];
                    try {
                        dec.readByteString(auth, (short) 0);
                    } catch (UserException e) {
                        UserException.throwIt((byte) 0x70);
                        break;
                    }
                    break;
                default:
                    UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                    break;
            }
        }
    }

}
