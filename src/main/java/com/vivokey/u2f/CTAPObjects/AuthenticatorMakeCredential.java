package com.vivokey.u2f.CTAPObjects;

import com.vivokey.u2f.CBORBase;
import com.vivokey.u2f.CBORDecoder;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class AuthenticatorMakeCredential {
    private byte[] dataHash;
    private PublicKeyCredentialRpEntity rp;
    private PublicKeyCredentialUserEntity user;
    private PublicKeyCredentialParams params;
    private boolean[] options = new boolean[2];
    // Representation of "id" in UTF8
    private static final byte[] UTF8_ID = {0x69, 0x64};
    // Representation of "name" in UTF8
    private static final byte[] UTF8_NAME = {0x6e, 0x61, 0x6d, 0x65};
    // Representation of "displayName" in UTF8
    private static final byte[] UTF8_DISPLAYNAME = {0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65};
    // Representation of "alg" in UTF8
    private static final byte[] UTF8_ALG = {0x61, 0x6c, 0x67};
    private static final byte[] UTF8_UV = {0x75, 0x76};
    private static final byte[] UTF8_RK = {0x72, 0x6b};
    private byte[] scratch1;
    private byte[] scratch2;

    /**
     * Parses a CBOR structure to create an AuthenticatorMakeCredential object
     * @param decoder the initialised decoder on the CBOR structure
     * @param vars a short array to store variables in
     */
    public AuthenticatorMakeCredential(CBORDecoder decoder, short[] vars) {
        // Start reading, we should get a map
        scratch1 = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        scratch2 = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        vars[4] = decoder.readMajorType(CBORBase.TYPE_MAP);
        // options[0] is rk - default false
        // options[1] is uv - default false
        options[0] = false;
        options[1] = false;
        // We now have the number of objects in the map
        // Read all the objects in map
        for(vars[6] = 0; vars[6] < vars[4]; vars[6]++) {
            // Read the ID type
            vars[5] = decoder.readRawByte();
            // Do based on the ID
            switch(vars[5]) {
                case (short) 1:
                    // 1, so the data here is a client data hash
                    vars[7] = decoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
                    // Create the data hash to store here
                    dataHash = new byte[vars[7]];
                    // Grab and store the data hash
                    decoder.readByteString(dataHash, (short) 0);
                    break;
                case (short) 2:
                    // Rp object, create it
                    rp = new PublicKeyCredentialRpEntity();
                    // Read the map length - should be 2
                    vars[7] = decoder.readMajorType(CBORBase.TYPE_MAP);
                    // If less than 2, error
                    if(vars[7] < (short) 2) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                    // Read the map iteratively
                    for(vars[0] = 0; vars[0] < vars[7]; vars[0]++) {

                        // Check the object we're looking at's type, it will be TEXT_STRING
                        vars[1] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                        // Read the text string in
                        decoder.readByteString(scratch1, (short) 0);
                        // Check if it equals id
                        if(Util.arrayCompare(scratch1, (short)0, UTF8_ID, (short) 0, (short) 2) == (byte) 0) {
                            // It does, so read its length
                            vars[1] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                            // Read the string into scratch
                            decoder.readByteString(scratch1, (short) 0);
                            // Set it
                            rp.setRp(scratch1, vars[1]);
                        } else 
                        // Check if it equals name, if not id
                        if(Util.arrayCompare(scratch1, (short) 0, UTF8_NAME, (short) 0, (short) 4) == (byte) 0) {
                            // It does, so read its length
                            vars[1] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                            // Read the string into scratch
                            decoder.readByteString(scratch1, (short) 0);
                            // Set it
                            rp.setName(scratch1, vars[1]);
                        }

                    }
                    break;
                case (short) 3:
                    // UserEntity, create
                    user = new PublicKeyCredentialUserEntity();
                    // Read the map length - should be at least 3
                    vars[7] = decoder.readMajorType(CBORBase.TYPE_MAP);
                    // If less than 2, error
                    if(vars[7] < (short) 3) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                    // Read the map iteratively
                    for(vars[0] = 0; vars[0] < vars[7]; vars[0]++) {
                        // Check the object we're looking at's type, it will be TEXT_STRING
                        vars[1] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                        // Read the text string in
                        decoder.readByteString(scratch1, (short) 0);
                        // Check if it equals id
                        if(Util.arrayCompare(scratch1, (short)0, UTF8_ID, (short) 0, (short) 2) == (byte) 0) {
                            // It does, so read its length
                            vars[1] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                            // Read the string into scratch
                            decoder.readByteString(scratch1, (short) 0);
                            // Set it
                            user.setId(scratch1, vars[1]);
                        } else 
                        // Check if it equals name, if not id
                        if(Util.arrayCompare(scratch1, (short) 0, UTF8_NAME, (short) 0, (short) 4) == (byte) 0) {
                            // It does, so read its length
                            vars[1] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                            // Read the string into scratch
                            decoder.readByteString(scratch1, (short) 0);
                            // Set it
                            user.setName(scratch1, vars[1]);
                        } else 
                        // Check if it equals displayName, if not those
                        if(Util.arrayCompare(scratch1, (short) 0, UTF8_DISPLAYNAME, (short) 0, (short) 11) == (byte) 0) {
                            // It does, so read its length
                            vars[1] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                            // Read the string into scratch
                            decoder.readByteString(scratch1, (short) 0);
                            // Set it
                            user.setDisplayName(scratch1, vars[1]);
                        }

                    }
                    break;
                case (short) 4:
                    // pubKeyCredParams - this is the type of credentials usable
                    // Read the array length
                    vars[0] = decoder.readMajorType(CBORBase.TYPE_ARRAY);
                    // Create the params object
                    params = new PublicKeyCredentialParams(vars[0]);
                    // Process the array
                    for(vars[1] = 0; vars[1] < vars[0]; vars[1]++) {
                        // Read the map length - should be 2
                        vars[2] = decoder.readMajorType(CBORBase.TYPE_MAP);
                        // Iterate over the map
                        for(vars[3] = 0; vars[3] < vars[2]; vars[3]++) {
                            vars[4] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                            decoder.readByteString(scratch1, (short) 0);
                            if(Util.arrayCompare(scratch1, (short) 0, UTF8_ALG, (short) 0, (short) 3) == (byte) 0) {
                                // Read the integer type (positive or negative)
                                if(decoder.getMajorType() == CBORBase.TYPE_UNSIGNED_INTEGER) {
                                    // Positive number
                                    vars[4] = decoder.readEncodedInteger(scratch2, (short) 0);
                                    if(vars[4] == 1) {
                                        // Single byte
                                        params.addAlgorithm(scratch2[0]);
                                    } else if (vars[4] == 2) {
                                        // A full short
                                        params.addAlgorithm(Util.makeShort(scratch2[0], scratch2[1]));
                                    }
                                } else if (decoder.getMajorType() == CBORBase.TYPE_NEGATIVE_INTEGER) {
                                    // Negative
                                    vars[4] = decoder.readEncodedInteger(scratch2, (short) 0);
                                    if(vars[4] == 1) {
                                        params.addAlgorithm((short) (-1 - scratch2[0]));
                                    } else if (vars[4] == 2) {
                                        // Full short
                                        params.addAlgorithm((short) (-1 - Util.makeShort(scratch2[0], scratch2[1])));
                                    }
                                }
                                
                            }
                        }
                        // Done
                    }
                    break;
                case (short) 7:
                    // Options map
                    // Parse the two rk and uv objects
                    // Read the map
                    vars[0] = decoder.readMajorType(CBORBase.TYPE_MAP);
                    for(vars[1] = 0; vars[1] < vars[0]; vars[1]++) {
                        // Parse the map
                        vars[2] = decoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                        decoder.readByteString(scratch1, (short) 0);
                        if(Util.arrayCompare(scratch1, (short) 0, UTF8_UV, (short) 0, (short) 2) == (short) 0) {
                            // Is the user validation bit
                            options[1] = decoder.readBoolean();
                        }
                        if(Util.arrayCompare(scratch1, (short) 0, UTF8_RK, (short) 0, (short) 2) == (short) 0) {
                            // Is the resident key bit
                            options[0] = decoder.readBoolean();
                        }
                    }
                case (short) 5:
                case (short) 6:
                default:
                    break;

            }
        }
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




}
