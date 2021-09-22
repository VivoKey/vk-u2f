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
                        UserException.throwIt((byte) 0x70);
                        break;
                    }
                    // Tag 1: kty
                    dec.readInt8();
                    // Value, must be 2
                    if (dec.readInt8() != (byte) 0x02) {
                        UserException.throwIt((byte) 0x71);
                        break;
                    }
                    // Tag 3: alg
                    dec.readInt8();
                    // Value, must be 24 (-25 is -1 - 24)
                    if (dec.readInt8() != (byte) 0x24) {
                        UserException.throwIt((byte) 0x72);
                        break;
                    }
                    // Tag -1: curve
                    dec.readInt8();
                    // Value, must be 1
                    if (dec.readInt8() != (byte) 0x01) {
                        UserException.throwIt((byte) 0x73);
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
                    encSalts = new byte[dec.readLength()];
                    dec.readByteString(encSalts, (short) 0);
                    break;
                case 0x03:
                    // Some kind of authentication
                    // Read it in
                    auth = new byte[dec.readLength()];
                    dec.readByteString(auth, (short) 0);
                    break;
                default:
                    UserException.throwIt((byte) 0x74);
                    break;
            }
        }
    }

}
