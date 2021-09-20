package com.vivokey.u2f;

import javacard.framework.JCSystem;
import javacard.framework.UserException;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;

// Stores the key agreement and associated details of the hmac-secret extension
public class HMACSecret {

    private ECPublicKey platformDhPub;
    private byte[] encSalts;
    private byte[] auth;

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
                    if (dec.readInt8() != (byte) 0x02) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Tag 3: alg
                    dec.readInt8();
                    // Value, must be 24 (-25 is -1 - 24)
                    if (dec.readInt8() != (byte) 0x24) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Tag -1: curve
                    dec.readInt8();
                    // Value, must be 1
                    if (dec.readInt8() != (byte) 0x01) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                        break;
                    }
                    // Tag -2: X-coord
                    dec.readInt8();
                    // Create a w to make the pubkey out of
                    byte[] w;
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
                    // Form the public key
                    platformDhPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC,
                            KeyBuilder.LENGTH_EC_FP_256, false);
                    // Copy the public key parameters over
                    KeyParams.sec256r1params(platformDhPub);
                    platformDhPub.setW(w, (short) 0, (short) 65);
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
                    UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                    break;
            }
        }
    }


    
}
