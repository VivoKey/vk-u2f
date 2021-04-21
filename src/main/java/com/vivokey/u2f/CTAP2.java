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

import javacard.framework.APDU;
import javacard.framework.JCSystem;

public class CTAP2 {

    private CBORDecoder cborDecoder;

    private byte[] ram1;
    private byte[] ram2;
    private byte[] ram3;
    private byte[] ram4;
    private byte[] ram5;
    private short readout;
    private static final byte CTAP1_ERR_SUCCESS = (byte) 0x00;
    private static final byte CTAP1_ERR_INVALID_COMMAND = (byte) 0x01;
    private static final byte CTAP1_ERR_INVALID_PARAMETER = (byte) 0x02;
    private static final byte CTAP1_ERR_INVALID_LENGTH = (byte) 0x03;
    private static final byte CTAP1_ERR_INVALID_SEQ = (byte) 0x04;
    private static final byte CTAP1_ERR_TIMEOUT = (byte) 0x05;
    private static final byte CTAP1_ERR_CHANNEL_BUSY = (byte) 0x06;
    private static final byte CTAP1_ERR_LOCK_REQUIRED = (byte) 0x0A;
    private static final byte CTAP1_ERR_INVALID_CHANNEL = (byte) 0x0B;
    private static final byte CTAP1_ERR_OTHER = (byte) 0x7F;

    private static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = (byte) 0x11;
    private static final byte CTAP2_ERR_INVALID_CBOR = (byte) 0x12;
    private static final byte CTAP2_ERR_MISSING_PARAMETER = (byte) 0x14;
    private static final byte CTAP2_ERR_LIMIT_EXCEEDED = (byte) 0x15;
    private static final byte CTAP2_ERR_UNSUPPORTED_EXTENSION = (byte) 0x16;
    private static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = (byte) 0x19;
    private static final byte CTAP2_ERR_PROCESSING = (byte) 0x21;
    private static final byte CTAP2_ERR_INVALID_CREDENTIAL = (byte) 0x22;
    private static final byte CTAP2_ERR_USER_ACTION_PENDING = (byte) 0x23;
    private static final byte CTAP2_ERR_OPERATION_PENDING = (byte) 0x24;
    private static final byte CTAP2_ERR_NO_OPERATIONS = (byte) 0x25;
    private static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = (byte) 0x26;
    private static final byte CTAP2_ERR_OPERATION_DENIED = (byte) 0x27;
    private static final byte CTAP2_ERR_KEY_STORE_FULL = (byte) 0x28;
    private static final byte CTAP2_ERR_NO_OPERATION_PENDING = (byte) 0x2A;
    private static final byte CTAP2_ERR_UNSUPPORTED_OPTION = (byte) 0x2B;
    private static final byte CTAP2_ERR_INVALID_OPTION = (byte) 0x2C;
    private static final byte CTAP2_ERR_KEEPALIVE_CANCEL = (byte) 0x2D;
    private static final byte CTAP2_ERR_NO_CREDENTIALS = (byte) 0x2E;
    private static final byte CTAP2_ERR_USER_ACTION_TIMEOUT = (byte) 0x2F;
    private static final byte CTAP2_ERR_NOT_ALLOWED = (byte) 0x30;
    private static final byte CTAP2_ERR_PIN_INVALID = (byte) 0x31;
    private static final byte CTAP2_ERR_PIN_BLOCKED = (byte) 0x32;
    private static final byte CTAP2_ERR_PIN_AUTH_INVALID = (byte) 0x33;
    private static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = (byte) 0x34;
    private static final byte CTAP2_ERR_PIN_NOT_SET = (byte) 0x35;
    private static final byte CTAP2_ERR_PIN_REQUIRED = (byte) 0x36;
    private static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = (byte) 0x37;
    private static final byte CTAP2_ERR_PIN_TOKEN_EXPIRED = (byte) 0x38;
    private static final byte CTAP2_ERR_REQUEST_TOO_LARGE = (byte) 0x39;
    private static final byte CTAP2_ERR_ACTION_TIMEOUT = (byte) 0x3A;
    private static final byte CTAP2_ERR_UP_REQUIRED = (byte) 0x3B;

    private static final byte FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL = (byte) 0x01;
    private static final byte FIDO2_AUTHENTICATOR_GET_ASSERTION = (byte) 0x02;
    private static final byte FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION = (byte) 0x08;
    private static final byte FIDO2_AUTHENTICATOR_GET_INFO = (byte) 0x04;
    private static final byte FIDO2_AUTHENTICATOR_CLIENT_PIN = (byte) 0x06;
    private static final byte FIDO2_AUTHENTICATOR_RESET = (byte) 0x07;

    
    public CTAP2() {
        // Need some scratchpad RAM
        ram1 = new byte[32];
        ram2 = new byte[256];
        ram3 = new byte[256];
        ram4 = new byte[256];
        ram5 = new byte[256];
        readout = (short) 0;
        // Create the CBOR decoder
        cborDecoder = new CBORDecoder();
        
    }

    public void handle(APDU apdu, byte[] buffer) {
        // Need to grab the CTAP command byte
        switch(buffer[apdu.getOffsetCdata()]) {
                case FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL:
                    authMakeCredential(apdu, buffer);
        }
    }


    public void authMakeCredential(APDU apdu, byte[] buffer) {
        cborDecoder.init((short) (apdu.getOffsetCdata()+1), (short) (apdu.getIncomingLength()-1));
        // Read the data hash
        readout = cborDecoder.readByteString(ram1, (byte) 0);
        // Read the rp (PublicKeyCredentialUserEntity object)
        short rpLen = cborDecoder.readByteString(ram2, (byte) 0);
        short userLen = cborDecoder.readByteString(ram3, (byte) 0);
        short pkParamLen = cborDecoder.readByteString(ram4, (byte) 0);
        // optionals
        short exclLen = cborDecoder.readByteString(ram5, (byte) 0);
    }

}
