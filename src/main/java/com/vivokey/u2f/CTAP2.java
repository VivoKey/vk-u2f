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

import com.vivokey.u2f.CTAPObjects.AuthenticatorMakeCredential;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.Signature;

public class CTAP2 {

    private CBORDecoder cborDecoder;

    private byte[] inBuf;
    private short[] vars;
    private CredentialArray discoverableCreds;
    private U2FApplet app;

    public static final byte CTAP1_ERR_SUCCESS = (byte) 0x00;
    public static final byte CTAP1_ERR_INVALID_COMMAND = (byte) 0x01;
    public static final byte CTAP1_ERR_INVALID_PARAMETER = (byte) 0x02;
    public static final byte CTAP1_ERR_INVALID_LENGTH = (byte) 0x03;
    public static final byte CTAP1_ERR_INVALID_SEQ = (byte) 0x04;
    public static final byte CTAP1_ERR_TIMEOUT = (byte) 0x05;
    public static final byte CTAP1_ERR_CHANNEL_BUSY = (byte) 0x06;
    public static final byte CTAP1_ERR_LOCK_REQUIRED = (byte) 0x0A;
    public static final byte CTAP1_ERR_INVALID_CHANNEL = (byte) 0x0B;
    public static final byte CTAP1_ERR_OTHER = (byte) 0x7F;

    public static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = (byte) 0x11;
    public static final byte CTAP2_ERR_INVALID_CBOR = (byte) 0x12;
    public static final byte CTAP2_ERR_MISSING_PARAMETER = (byte) 0x14;
    public static final byte CTAP2_ERR_LIMIT_EXCEEDED = (byte) 0x15;
    public static final byte CTAP2_ERR_UNSUPPORTED_EXTENSION = (byte) 0x16;
    public static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = (byte) 0x19;
    public static final byte CTAP2_ERR_PROCESSING = (byte) 0x21;
    public static final byte CTAP2_ERR_INVALID_CREDENTIAL = (byte) 0x22;
    public static final byte CTAP2_ERR_USER_ACTION_PENDING = (byte) 0x23;
    public static final byte CTAP2_ERR_OPERATION_PENDING = (byte) 0x24;
    public static final byte CTAP2_ERR_NO_OPERATIONS = (byte) 0x25;
    public static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = (byte) 0x26;
    public static final byte CTAP2_ERR_OPERATION_DENIED = (byte) 0x27;
    public static final byte CTAP2_ERR_KEY_STORE_FULL = (byte) 0x28;
    public static final byte CTAP2_ERR_NO_OPERATION_PENDING = (byte) 0x2A;
    public static final byte CTAP2_ERR_UNSUPPORTED_OPTION = (byte) 0x2B;
    public static final byte CTAP2_ERR_INVALID_OPTION = (byte) 0x2C;
    public static final byte CTAP2_ERR_KEEPALIVE_CANCEL = (byte) 0x2D;
    public static final byte CTAP2_ERR_NO_CREDENTIALS = (byte) 0x2E;
    public static final byte CTAP2_ERR_USER_ACTION_TIMEOUT = (byte) 0x2F;
    public static final byte CTAP2_ERR_NOT_ALLOWED = (byte) 0x30;
    public static final byte CTAP2_ERR_PIN_INVALID = (byte) 0x31;
    public static final byte CTAP2_ERR_PIN_BLOCKED = (byte) 0x32;
    public static final byte CTAP2_ERR_PIN_AUTH_INVALID = (byte) 0x33;
    public static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = (byte) 0x34;
    public static final byte CTAP2_ERR_PIN_NOT_SET = (byte) 0x35;
    public static final byte CTAP2_ERR_PIN_REQUIRED = (byte) 0x36;
    public static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = (byte) 0x37;
    public static final byte CTAP2_ERR_PIN_TOKEN_EXPIRED = (byte) 0x38;
    public static final byte CTAP2_ERR_REQUEST_TOO_LARGE = (byte) 0x39;
    public static final byte CTAP2_ERR_ACTION_TIMEOUT = (byte) 0x3A;
    public static final byte CTAP2_ERR_UP_REQUIRED = (byte) 0x3B;

    private static final byte FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL = (byte) 0x01;
    private static final byte FIDO2_AUTHENTICATOR_GET_ASSERTION = (byte) 0x02;
    private static final byte FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION = (byte) 0x08;
    private static final byte FIDO2_AUTHENTICATOR_GET_INFO = (byte) 0x04;
    private static final byte FIDO2_AUTHENTICATOR_CLIENT_PIN = (byte) 0x06;
    private static final byte FIDO2_AUTHENTICATOR_RESET = (byte) 0x07;

    
    public CTAP2(U2FApplet attest) {

        // 1024 bytes of a transient buffer for read-in
        inBuf = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_DESELECT);
        vars = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        // Create the CBOR decoder
        cborDecoder = new CBORDecoder();
        discoverableCreds = new CredentialArray((short) 10);
        app = attest;
    }

    public void handle(APDU apdu, byte[] buffer) {
        vars[4] = apdu.setIncomingAndReceive();
        // Check if the APDU is too big, we only handle 1024 byte
        if(apdu.getIncomingLength() > 1024) {
            returnError(apdu, buffer, CTAP2_ERR_REQUEST_TOO_LARGE);
            return;
        }
        vars[3] = apdu.getIncomingLength();
        // Read into the buffer, as messages can be pretty large
        vars[0] = (short) (vars[4] - apdu.getOffsetCdata());
        vars[1] = apdu.getOffsetCdata();
        vars[2] = 0;
        // Copy first part of the APDU
        Util.arrayCopy(buffer, vars[1], inBuf, vars[2], vars[0]);
        // Source offset
        vars[1] = 0;
        vars[2] = vars[0];
        while(apdu.getCurrentState() == APDU.STATE_PARTIAL_INCOMING) {
            // Grab more bytes, set new length, etc
            vars[0] = apdu.receiveBytes(vars[1]);
            Util.arrayCopy(buffer, vars[1], inBuf, vars[2], vars[0]);
            // Source offset
            vars[1] = 0;
            vars[2] += vars[0];
        }
        // Need to grab the CTAP command byte
        switch(inBuf[0]) {
                case FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL:
                    authMakeCredential(apdu, buffer, inBuf, vars[3]);
                default:
                    returnError(apdu, buffer, CTAP2_ERR_OPERATION_DENIED);
        }
    }


    public void authMakeCredential(APDU apdu, byte[] buffer, byte[] inBuf, short bufLen) {
        try {
            // Init the decoder
            cborDecoder.init(inBuf, (short) 1, bufLen);
            // create a credential object
            AuthenticatorMakeCredential cred = new AuthenticatorMakeCredential(cborDecoder, vars);
            
            if(cred.isResident()) {
                // Create the actual credential
                StoredCredential residentCred = null;
                switch (cred.getAlgorithm()) {
                    case Signature.ALG_ECDSA_SHA_256:
                        residentCred = new StoredES256Credential(cred);
                    case Signature.ALG_RSA_SHA_256_PKCS1:
                        residentCred = new StoredRS256Credential(cred);
                    default:
                        returnError(apdu, buffer, CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                }
                // Add the credential to the resident storage, overwriting if necessary
                addResident(apdu, buffer, residentCred);
                
                // Create the data array representing this credential

            }
        } catch (ISOException e) {
            // We redo ISOExceptions as a CBOR error
            returnError(apdu, buffer, CTAP2_ERR_INVALID_CBOR);
        }
        
    }

    private void addResident(APDU apdu, byte[] buffer, StoredCredential cred) {
        // Add a Discoverable Credential (resident)
        try {
            discoverableCreds.addCredential(cred);
        } catch (ISOException e) {
            returnError(apdu, buffer, (byte) CTAP2_ERR_INVALID_CREDENTIAL);
        }
    }
    /**
     * Return an error via APDU - an error on the FIDO2 side is considered a success in APDU-land so we send a response. 
     * @param apdu shared APDU object
     * @param buffer APDU buffer
     * @param err error code
     */
    public void returnError(APDU apdu, byte[] buffer, byte err) {
        buffer[0] = err;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

}
