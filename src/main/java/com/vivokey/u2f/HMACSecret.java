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
                    for (short j = 0; j < coseLen; j++) {
                        short key = 0;
                        if (dec.getMajorType() == CBORBase.TYPE_NEGATIVE_INTEGER) {
                            key = (short) ((short) (-1) - dec.readInt8());
                        } else if (dec.getMajorType() == CBORBase.TYPE_UNSIGNED_INTEGER) {
                            key = dec.readInt8();
                        } else {
                            UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_CBOR);
                            break;
                        }
                        switch (key) {
                            case 1:
                                // Value should be 2
                                if (dec.readInt8() != 2) {
                                    UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                                    break;
                                }
                                break;
                            case 3:
                                // Value, must be 24 (-25 is -1 - 24)
                                if (dec.readInt8() != 24) {
                                    UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                                    break;
                                }
                                break;
                            case -1:
                                // Crv, should be 1
                                if (dec.readInt8() != 1) {
                                    UserException.throwIt(CTAP2.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                                    break;
                                }
                                break;
                            case -2:
                                try {
                                    dec.readByteString(w, (short) 1);
                                } catch (Exception e) {
                                    UserException.throwIt((byte) 0x81);
                                    break;
                                }
                                break;
                            case -3:
                                try {
                                    dec.readByteString(w, (short) 33);
                                } catch (Exception e) {
                                    UserException.throwIt((byte) 0x82);
                                    break;
                                }
                                break;
                            default:
                                UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_CBOR);
                                break;
                        }
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
                        UserException.throwIt((byte) 0x83);
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
                        UserException.throwIt((byte) 0x80);
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
