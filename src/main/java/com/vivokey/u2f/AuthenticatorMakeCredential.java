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
import javacard.framework.UserException;
import javacard.framework.Util;

public class AuthenticatorMakeCredential {
    public byte[] dataHash;
    private PublicKeyCredentialRpEntity rp;
    private PublicKeyCredentialUserEntity user;
    private PublicKeyCredentialParams params;
    private boolean[] options = new boolean[2];

    public PublicKeyCredentialDescriptor[] exclude;

    /**
     * Parses a CBOR structure to create an AuthenticatorMakeCredential object
     * 
     * @param decoder the initialised decoder on the CBOR structure
     * @param vars    a short array to store variables in
     */
    public AuthenticatorMakeCredential(CBORDecoder decoder) throws UserException {
        short[] vars;
        try {
            vars = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            vars = new short[8];
        }
        // Start reading, we should get a map
        byte[] scratch1;
        try {
            scratch1 = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            scratch1 = new byte[64];
        }
        byte[] scratch2;
        try {
            scratch2 = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            scratch2 = new byte[64];
        }
        vars[4] = decoder.readMajorType(CBORBase.TYPE_MAP);
        // options[0] is rk - default true for us
        // options[1] is uv - default false
        options[0] = true;
        options[1] = false;
        // We now have the number of objects in the map
        // Read all the objects in map
        for (vars[6] = 0; vars[6] < vars[4]; vars[6]++) {
            // Read the ID type
            vars[5] = decoder.readInt8();
            // Do based on the ID
            switch (vars[5]) {
                case (short) 1:
                    // Grab and store the data hash
                    // To prevent extra copies, reading raw
                    vars[7] = decoder.readLength();
                    dataHash = new byte[vars[7]];
                    decoder.readRawByteArray(dataHash, (short) 0, vars[7]);
                    break;
                case (short) 2:
                    // Rp object, create it
                    rp = new PublicKeyCredentialRpEntity();
                    // Read the map length - should be 2
                    vars[7] = decoder.readMajorType(CBORBase.TYPE_MAP);
                    // If less than 2, error
                    if (vars[7] < (short) 2) {
                        UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_CBOR);
                    }
                    // Read the map iteratively
                    for (vars[0] = 0; vars[0] < vars[7]; vars[0]++) {
                        // Read the text string in
                        vars[1] = decoder.readTextString(scratch1, (short) 0);
                        // Check if it equals id
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ID, (short) 0,
                                (short) 2) == (byte) 0) {
                            // It does, so read its length
                            vars[1] = decoder.readTextString(scratch1, (short) 0);
                            // Set it
                            rp.setRp(scratch1, vars[1]);
                        } else
                        // Check if it equals name, if not id
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_NAME, (short) 0,
                                (short) 4) == (byte) 0) {
                            // Read the string into scratch
                            vars[1] = decoder.readTextString(scratch1, (short) 0);
                            // Set it
                            rp.setName(scratch1, vars[1]);
                        }

                    }
                    break;
                case (short) 3:

                    // UserEntity, create
                    user = new PublicKeyCredentialUserEntity();
                    // Read the map length
                    vars[7] = decoder.readMajorType(CBORBase.TYPE_MAP);
                   
                    // Read the map iteratively
                    for (vars[0] = 0; vars[0] < vars[7]; vars[0]++) {
                        try {
                            // Read the text string in
                        vars[1] = decoder.readTextString(scratch1, (short) 0);
                        // Check if it equals id
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ID, (short) 0,
                                (short) 2) == (byte) 0) {
                            // Read the string into scratch
                            vars[1] = decoder.readByteString(scratch1, (short) 0);
                            // Set it
                            user.setId(scratch1, (short) 0, vars[1]);
                        } else
                        // Check if it equals name, if not id
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_NAME, (short) 0,
                                (short) 4) == (byte) 0) {
                            // Read the string into scratch
                            vars[1] = decoder.readTextString(scratch1, (short) 0);
                            // Set it
                            user.setName(scratch1, vars[1]);
                        } else
                        // Check if it equals displayName, if not those
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_DISPLAYNAME, (short) 0,
                                (short) 11) == (byte) 0) {
                            // Read the string into scratch
                            vars[1] = decoder.readTextString(scratch1, (short) 0);
                            // Set it
                            user.setDisplayName(scratch1, vars[1]);
                        } else
                        // If icon, even
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ICON, (short) 0, (short) 4) == (byte) 0) {
                            try {
                                // Read the string into scratch
                            vars[6] = decoder.readTextString(scratch2, (short) 0);
                            user.setIcon(scratch2, vars[6]);
                            } catch (ArrayIndexOutOfBoundsException e) {
                                UserException.throwIt((byte) (0x10 | vars[6]));
                                break;
                            }
                        } else  {
                            // Is optional, so we need to skip the value
                            decoder.skipEntry();
                        }
                    } catch (ArrayIndexOutOfBoundsException e) {
                        UserException.throwIt((byte) (0x40 | vars[0]));
                        break;
                    }

                    }
                    break;
                case (short) 4:
                    vars[0] = decoder.readMajorType(CBORBase.TYPE_ARRAY);

                    // Create the params object
                    params = new PublicKeyCredentialParams(vars[0]);
                    // Process the array
                    for (vars[1] = 0; vars[1] < vars[0]; vars[1]++) {
                        // Read the map length - should be 2
                        vars[2] = decoder.readMajorType(CBORBase.TYPE_MAP);
                        if(vars[2] != 2) {
                            UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_CBOR);
                        }
                        // Iterate over the map
                        for (vars[3] = 0; vars[3] < vars[2]; vars[3]++) {
                            vars[4] = decoder.readTextString(scratch1, (short) 0);
                            if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_ALG, (short) 0,
                                    (short) 3) == (byte) 0) {
                                // Read the integer type (positive or negative)
                                if (decoder.getMajorType() == CBORBase.TYPE_UNSIGNED_INTEGER) {
                                    // Positive number
                                    vars[4] = decoder.readEncodedInteger(scratch2, (short) 0);
                                    if (vars[4] == 1) {
                                        // Single byte
                                        params.addAlgorithm(scratch2[0]);
                                    } else if (vars[4] == 2) {
                                        // A full short
                                        params.addAlgorithm(Util.makeShort(scratch2[0], scratch2[1]));
                                    }
                                } else if (decoder.getMajorType() == CBORBase.TYPE_NEGATIVE_INTEGER) {
                                    // Negative
                                    vars[4] = decoder.readEncodedInteger(scratch2, (short) 0);
                                    if (vars[4] == 1) {
                                        params.addAlgorithm((short) (-1 - scratch2[0]));
                                    } else if (vars[4] == 2) {
                                        // Full short
                                        params.addAlgorithm((short) (-1 - Util.makeShort(scratch2[0], scratch2[1])));
                                    }
                                }

                            } else if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_TYPE, (short) 0, (short) 4) == (byte) 0) {
                                // Public key type
                                // Check it
                                vars[4] = decoder.readTextString(scratch1, (short) 0);
                                if(Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_PUBLIC_KEY, (short) 0, (short) 10) != (byte) 0) {
                                    UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_CBOR);
                                }
                            } else {
                                UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_CBOR);
                            }
                        }
                        // Done
                    }

                    break;
                case (short) 5:
                    // Credential exclusion stuff
                    // Parse it
                    vars[2] = decoder.readMajorType(CBORBase.TYPE_ARRAY);
                    exclude = new PublicKeyCredentialDescriptor[vars[2]];
                    for (vars[0] = 0; vars[0] < vars[2]; vars[0]++) {
                        // Read the map. It has 2 things in it.
                        vars[1] = decoder.readMajorType(CBORBase.TYPE_MAP);
                        if (vars[1] != 2) {
                            UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_CBOR);
                        }
                        // Read the id - it must be first
                        decoder.skipEntry();
                        // Read the actual id
                        vars[1] = decoder.readByteString(scratch1, (short) 0);
                        exclude[vars[0]] = new PublicKeyCredentialDescriptor(scratch1, (short) 0, vars[1]);
                        // Skip the next two entries (pubkey type)
                        decoder.skipEntry();
                        decoder.skipEntry();
                    }
                    break;
                case (short) 7:
                    // Options map
                    // Parse the two rk and uv objects
                    // Read the map
                    vars[0] = decoder.readMajorType(CBORBase.TYPE_MAP);
                    for (vars[1] = 0; vars[1] < vars[0]; vars[1]++) {
                        // Parse the map
                        vars[2] = decoder.readTextString(scratch1, (short) 0);
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_UV, (short) 0,
                                (short) 2) == (short) 0) {
                            // Is the user validation bit
                            options[1] = decoder.readBoolean();
                        }
                        if (Util.arrayCompare(scratch1, (short) 0, Utf8Strings.UTF8_RK, (short) 0,
                                (short) 2) == (short) 0) {
                            // Is the resident key bit

                            decoder.readBoolean();
                        }
                    }
                    break;
                
                case (short) 6:
                default:
                    // Skip it transparently
                    decoder.skipEntry();
                    break;

            }

        }

        // We're done, I guess
    }

    public PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public boolean isResident() {
        return options[0];
    }

    public byte getAlgorithm() {
        return params.getAlgorithm();
    }

    public boolean isExclude() {
        return (exclude != null && exclude.length > 0);
    }

    /**
     * Reads the clientDataHash into a buffer.
     * 
     * @param outBuf The buffer to read into.
     * @param outOff the offset to begin at.
     * @return the length of the data read out.
     */
    public short getDataHash(byte[] outBuf, short outOff) {
        Util.arrayCopy(dataHash, (short) 0, outBuf, outOff, (short) dataHash.length);
        return (short) dataHash.length;
    }

}
