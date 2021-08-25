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

public class AuthenticatorGetAssertion {
    public byte[] rpId;
    byte[] clientDataHash;
    boolean[] options;
    PublicKeyCredentialDescriptor[] allow;

    public AuthenticatorGetAssertion(CBORDecoder decoder) throws UserException {

        short[] vars;
        try {
            vars = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            vars = new short[8];
        }
        // Create options
        options = new boolean[2];
        // UP 
        options[0] = true;
        // UV
        options[1] = false;
        vars[0] = decoder.readMajorType(CBORBase.TYPE_MAP);
        // Create scratch
        byte[] scratch;
        try {
            scratch = JCSystem.makeTransientByteArray((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        } catch (Exception e) {
            scratch = new byte[64];
        }
        for(vars[7] = 0; vars[7] < vars[0]; vars[7]++ ) {
            vars[1] = decoder.readInt8();
            switch(vars[1]) {
                case 0x01:
                    // RpId
                    vars[2] = decoder.readTextString(scratch, (short) 0);
                    rpId = new byte[vars[2]];
                    // Copy to it
                    Util.arrayCopy(scratch, (short) 0, rpId, (short) 0, vars[2]);
                    break;
                case 0x02:
                    // clientDataHash
                    vars[2] = decoder.readByteString(scratch, (short) 0);
                    clientDataHash = new byte[vars[2]];
                    Util.arrayCopy(scratch, (short) 0, clientDataHash, (short) 0, vars[2]);
                    break;
                case 0x03:
                    // allowList
                    // Read the array
                    vars[2] = decoder.readMajorType(CBORBase.TYPE_ARRAY);
                    allow = new PublicKeyCredentialDescriptor[vars[2]];
                    for(vars[0] = 0; vars[0] < vars[2]; vars[0]++) {
                        // Read the map. It has 2 things in it.
                        vars[1] = decoder.readMajorType(CBORBase.TYPE_MAP);
                        if(vars[1] != 2) {
                            UserException.throwIt(CTAP2.CTAP2_ERR_INVALID_CBOR);
                        }
                        // Read the id - it must be first
                        decoder.skipEntry();
                        // Read the actual id
                        vars[1] = decoder.readByteString(scratch, (short) 0);
                        allow[vars[0]] = new PublicKeyCredentialDescriptor(scratch, (short) 0, vars[1]);
                        // Skip the next two entries (pubkey type)
                        decoder.skipEntry();
                        decoder.skipEntry();
                    }
                    break;
                case 0x05:
                    // Options - two important things here
                    vars[2] = decoder.readMajorType(CBORBase.TYPE_MAP);
                    for(vars[3] = 0; vars[3] < vars[2]; vars[3]++) {
                        // Read the text string
                        decoder.readTextString(scratch, (short) 0);
                        if(Util.arrayCompare(scratch, (short) 0, Utf8Strings.UTF8_UP, (short) 0, (short) 2) == 0) {
                            // Is the UP param
                            options[0] = decoder.readBoolean();
                        } else if (Util.arrayCompare(scratch, (short) 0, Utf8Strings.UTF8_UV, (short) 0, (short) 2) == 0) {
                            // Is the UV param
                            options[1] = decoder.readBoolean();
                        }
                    }
                    break;
                case 0x04:
                    // Extensions - we mostly ignore
                    decoder.skipEntry();
                case 0x06:
                    // Pin stuff
                    decoder.skipEntry();
                case 0x07:
                    // Pin protocol
                    decoder.skipEntry();
                default:
                    UserException.throwIt(CTAP2.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            }

        }
        // We should check we have our "mandatory" options
        if(rpId == null || clientDataHash == null) {
            UserException.throwIt(CTAP2.CTAP2_ERR_MISSING_PARAMETER);
        }
        // Good to go I guess

    }

    public short getHash(byte[] buf, short off) {
        Util.arrayCopy(clientDataHash, (short) 0, buf, off, (short) clientDataHash.length);
        return (short) clientDataHash.length;
    }

    public boolean hasAllow() {
        return (allow != null && allow.length > 0);
    }
    
}
