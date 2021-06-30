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
    // Representation of "id" in UTF8
    private static byte[] UTF8_ID = {0x69, 0x64};
    // Representation of "type" in UTF8
    private static byte[] UTF8_TYPE = {0x74, 0x79, 0x70, 0x65};
    // Representation of "name" in UTF8
    private static byte[] UTF8_NAME = {0x6e, 0x61, 0x6d, 0x65};
    // Representation of "displayName" in UTF8
    private static byte[] UTF8_DISPLAYNAME = {0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65};
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
            }
        }    
    }


}
