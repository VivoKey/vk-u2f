package com.vivokey.u2f;

import javacard.framework.JCSystem;
import javacard.framework.UserException;

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
                    // Tag 1: kty
                    dec.readInt8();
                    // Value, must be 2
                    if (dec.readInt8() != (byte) 2) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Tag 3: alg
                    dec.readInt8();
                    // Value, must be 24 (-25 is -1 - 24)
                    if (dec.readInt8() != (byte) 24) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Tag -1: curve
                    dec.readInt8();
                    // Value, must be 1
                    if (dec.readInt8() != (byte) 1) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Tag -2: X-coord
                    dec.readInt8();
                    // Initialise w to make the pubkey out of
                    try {
                        w = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
                    } catch (Exception e) {
                        w = new byte[65];
                    }
                    w[0] = 0x04;
                    // Read the X-coordinate in
                    dec.readByteString(w, (short) 1);
                    // Tag -3: Y-coord
                    dec.readInt8();
                    // Read the Y-coordinate in
                    dec.readByteString(w, (short) 33);
                    break;
                case 0x02:
                    // This is some kind of salting thing
                    // Read it in
                    byte[] tmp = new byte[64];
                    short len2 = dec.readByteString(tmp, (short) 0);
                    if(len2 == 32) {
                        encSalts = new byte[32];
                        System.arraycopy(tmp, (short) 0, encSalts, (short) 0, (short) 32);
                    } else if(len2 == 64) {
                        encSalts = new byte[64];
                        System.arraycopy(tmp, (short) 0, encSalts, (short) 0, (short) 64);
                    } else {
                        UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_OPTION);
                    }
                    break;
                case 0x03:
                    // Some kind of authentication
                    // Read it in
                    auth = new byte[16];
                    dec.readByteString(auth, (short) 0);
                    break;
                default:
                    UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                    break;
            }
        }
    }

}
