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
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.Signature;

public class CTAP2 {

    private CBORDecoder cborDecoder;
    private CBOREncoder cborEncoder;

    private byte[] inBuf;
    private byte[] scratch;
    private short[] vars;
    private CredentialArray discoverableCreds;
    private MessageDigest sha;
    private AttestationKeyPair attestation;

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
    // AAGUID - this uniquely identifies the type of authenticator we have built.
    // If you're reusing this code, please generate your own GUID and put it here - this is unique to manufacturer and device model.
    public static final byte[] aaguid = {(byte) 0xd7, (byte) 0xa4, (byte) 0x23, (byte) 0xad, (byte) 0x3e, (byte) 0x19, (byte) 0x44, (byte) 0x92, (byte) 0x92, (byte) 0x00, (byte) 0x78, (byte) 0x13, (byte) 0x7d, (byte) 0xcc, (byte) 0xc1, (byte) 0x36};
    
    public CTAP2() {

        // 1200 bytes of a transient buffer for read-in and out
        inBuf = JCSystem.makeTransientByteArray((short) 1200, JCSystem.CLEAR_ON_DESELECT);
        scratch = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        vars = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        // Create the CBOR decoder
        cborDecoder = new CBORDecoder();
        cborEncoder = new CBOREncoder();
        discoverableCreds = new CredentialArray((short) 10);
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        attestation = new AttestationKeyPair();

    }

    public void handle(APDU apdu, byte[] buffer) {
        vars[4] = apdu.setIncomingAndReceive();
        // Check if the APDU is too big, we only handle 1200 byte
        if(apdu.getIncomingLength() > 1200) {
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
                    break;
                case FIDO2_AUTHENTICATOR_GET_ASSERTION:
                    authGetAssertion(apdu, buffer, inBuf, vars[3]);
                default:
                    returnError(apdu, buffer, CTAP2_ERR_OPERATION_DENIED);
        }
    }


    public void authMakeCredential(APDU apdu, byte[] buffer, byte[] inBuf, short bufLen) {
        try {
            // Init the decoder
            cborDecoder.init(inBuf, (short) 1, bufLen);
            // create a credential object
            AuthenticatorMakeCredential cred = new AuthenticatorMakeCredential(cborDecoder);
            
            if(cred.isResident()) {
                // Create the actual credential
                StoredCredential residentCred = null;
                switch (cred.getAlgorithm()) {
                    case Signature.ALG_ECDSA_SHA_256:
                        residentCred = new StoredES256Credential(cred);
                    case Signature.ALG_RSA_SHA_256_PKCS1:
                        residentCred = new StoredRS256Credential(cred);
                    case Signature.ALG_RSA_SHA_256_PKCS1_PSS:
                        residentCred = new StoredPS256Credential(cred);
                    default:
                        returnError(apdu, buffer, CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                }
                // Add the credential to the resident storage, overwriting if necessary
                addResident(apdu, buffer, residentCred);
                // Initialise the output buffer, for CBOR writing.
                // output buffer needs 0x00 as first byte as status code...
                inBuf[0] = 0x00;
                cborEncoder.init(inBuf, (short) 1, (short) 1200);
                // Create a map in the buffer
                vars[0] = cborEncoder.startMap((short) 3);
                // Create the SHA256 hash of the RP ID
                residentCred.rp.getRp(scratch, (short) 0);
                // Override it 
                sha.doFinal(scratch, (short) 0, residentCred.rp.getRpLen(), scratch, (short) 0);
                // Set flags - User presence, user verified, attestation present
                scratch[32] = (byte) 0x45;
                // Set the signature counter
                residentCred.readCounter(scratch, (short) 33);
                // Read the credential details in
                vars[0] += residentCred.getAttestedData(scratch, (short) 37);
                // Put it into the CBOR map
                cborEncoder.encodeTextString(Utf8Strings.UTF8_AUTHDATA, (short) 0, (short) 8);
                cborEncoder.encodeByteString(scratch, (short) 0, vars[0]);
                // Attach the attestation statement format identifier
                cborEncoder.encodeTextString(Utf8Strings.UTF8_FMT, (short) 0, (short) 3);
                cborEncoder.encodeTextString(Utf8Strings.UTF8_PACKED, (short) 0, (short) 6);
                // Generate and then attach the attestation format
                cborEncoder.encodeTextString(Utf8Strings.UTF8_ATTSTMT, (short)0, (short) 7);
                // First off create a byte array for the attestation packed array, as it can get kinda big. 
                byte[] packed;
                try {
                    // Try and use RAM
                    packed = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_RESET);
                } catch (Exception e) {
                    // Not enough RAM - use a non-transient array
                    packed = new byte[1024];
                }
                // Create a second encoder to encode the packed attestation statement
                CBOREncoder enc2 = new CBOREncoder();
                enc2.init(packed, (short) 0, (short) 1024);
                // Create a map with 3 things
                vars[1] = enc2.startMap((short) 3);
                // Add the alg label
                vars[1] += enc2.encodeTextString(Utf8Strings.UTF8_ALG, (short) 0, (short) 3);
                // Add the actual algorithm - -7 is 6 as a negative
                vars[1] += enc2.encodeNegativeUInt8((byte) 6);
                // Add the actual signature, we should generate this
                vars[1] += enc2.encodeTextString(Utf8Strings.UTF8_SIG, (short) 0, (short) 3);
                // The signature is over the scratch data, first, but with the client data appended
                vars[0] += cred.getDataHash(scratch, vars[0]);
                // Sign into the scratch buffer, but at vars[0] + 1
                vars[2] = attestation.sign(scratch, (short) 0, vars[0], scratch, (short) (vars[0] + 1));
                // Create a DER encoding, ffs
                scratch[vars[0] + vars[2] + 1] = (byte) 0x30;
                // Skip the next one, as it's length of total data - we'll make vars[3] this
                vars[3] = 3;
                // This one's 0x02 which is integer type
                scratch[vars[0] + vars[2] + vars[3]++] = (byte) 0x02;
                // This is length of r, the first half of the signature - it'll always be 32 bytes due to signatures being 64
                scratch[vars[0] + vars[2] + vars[3]++] = (byte) 0x20;
                // Copy r in
                Util.arrayCopy(scratch, (short) (vars[0] + 1), scratch, scratch[vars[0] + vars[2] + vars[3]], (short) 32);
                vars[3] += 32;
                // Set the type of s - integer
                scratch[vars[0] + vars[2] + vars[3]++] = (byte) 0x02;
                // Set length of s - 32 bytes
                scratch[vars[0] + vars[2] + vars[3]++] = (byte) 0x20;
                // Copy s in
                Util.arrayCopy(scratch, (short) (vars[0] + 33), scratch, scratch[vars[0] + vars[2] + vars[3]], (short) 32);
                vars[3] += 32;
                // Set the length of the data
                scratch[vars[0] + vars[2] + 2] = (byte) vars[3];
                // Set this into the encoder
                enc2.encodeByteString(scratch, scratch[vars[0] + vars[2] + 1], (short) (vars[3] + 1));
                // Set the x509 now
                enc2.encodeTextString(Utf8Strings.UTF8_X5C, (short) 0, (short) 3);
                enc2.encodeByteString(attestation.x509cert, (short) 0, (short) attestation.x509cert.length);
                // Now set this whole array into the other CBOR
                cborEncoder.encodeByteString(packed, (short) 0, (short) (enc2.getCurrentOffset() - 1));
                // We're actually done, send this out
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) (cborEncoder.getCurrentOffset() - 1));
                apdu.sendBytesLong(inBuf, (short) 0, (short) (cborEncoder.getCurrentOffset() - 1));
            }
        } catch (ISOException e) {
            // We redo ISOExceptions as a CBOR error
            returnError(apdu, buffer, CTAP2_ERR_INVALID_CBOR);
        }
        
    }


    public void authGetAssertion(APDU apdu, byte[] buffer, byte[] inBuf, short bufLen) {
        try {
            // Decode the CBOR array for the assertion
            cborDecoder.init(inBuf, (short) 1, bufLen);
            AuthenticatorGetAssertion assertion = new AuthenticatorGetAssertion(cborDecoder);
            // Match the assertion to the credential
            // Get a list of matching credentials
            StoredCredential[] matchedCreds = findCredentials(apdu, buffer, assertion);
            // Use the first one; this complies with both ideas - use the most recent match if no allow list, use any if an allow list existed
            if(matchedCreds[0] == null) {
                returnError(apdu, buffer, CTAP2_ERR_NO_CREDENTIALS);
            }
            // Create the authenticatorData to sign
            sha.doFinal(assertion.rpId, (short) 0, (short) assertion.rpId.length, scratch, (short) 0);
            scratch[32] = 0x05;
            matchedCreds[0].readCounter(scratch, (short) 33);
            // Copy the hash in
            vars[2] = assertion.getHash(scratch, (short) 37);
            // Create the output

            // Status flags first
            inBuf[0] = 0x00;
            // Create the encoder
            cborEncoder.init(inBuf, (short) 1, (short) 1199);
            // Determine if we need 4 or 5 in the array
            if(matchedCreds.length > 1) {
                cborEncoder.startMap((short) 5);
            } else {
                cborEncoder.startMap((short) 4);
            }
            // Tag 1, credential data
            cborEncoder.encodeUInt8((byte) 0x01);
            // Start a map, which is all the PublicKeyCredentialDescriptor is
            cborEncoder.startMap((short) 2);
            // Put the key for the type
            cborEncoder.encodeTextString(Utf8Strings.UTF8_TYPE, (short) 0, (short) 4);
            // Put the value
            cborEncoder.encodeTextString(Utf8Strings.UTF8_PUBLIC_KEY, (short) 0, (short) 10);
            // Put the id key
            cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
            // Put the value, which is a byte array
            cborEncoder.encodeByteString(matchedCreds[0].id, (short) 0, (short) matchedCreds[0].id.length);
            // Done with tag 1
            cborEncoder.encodeUInt8((byte) 0x02);
            // Tag 2, which is the Authenticator bindings data
            cborEncoder.encodeByteString(scratch, (short) 0, (short) (vars[2] + 36));
            // Tag 3, the signature of said data.
            // Sign the data 
            vars[3] = matchedCreds[0].performSignature(scratch, (short) 0, (short) (vars[2] + 36), scratch, (short) (vars[2] + 37));
            // Put the tag in
            cborEncoder.encodeUInt8((byte) 0x03);
            // Put the data in
            cborEncoder.encodeByteString(scratch, (short) (vars[2]+37), vars[3]);
            // Tag 4, user details
            cborEncoder.encodeUInt8((byte) 0x04);
            // Start the PublicKeyCredentialUserEntity map
            cborEncoder.startMap((short) 3);
            cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
            cborEncoder.encodeByteString(matchedCreds[0].user.id, (short) 0, (short) matchedCreds[0].user.id.length);
            // The displayName
            cborEncoder.encodeTextString(Utf8Strings.UTF8_DISPLAYNAME, (short) 0, (short) 11);
            cborEncoder.encodeTextString(matchedCreds[0].user.displayName.str, (short) 0, matchedCreds[0].user.displayName.len);
            // The name
            cborEncoder.encodeTextString(Utf8Strings.UTF8_NAME, (short) 0, (short) 4);
            cborEncoder.encodeTextString(matchedCreds[0].user.name.str, (short) 0, matchedCreds[0].user.name.len);
            // Done tag 4
            if(matchedCreds.length > 1) {
                // Tag 5
                cborEncoder.encodeUInt8((byte) 0x05);
                cborEncoder.encodeUInt8((byte) matchedCreds.length);
            }
            // Emit this as a response
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) (cborEncoder.getCurrentOffset()-1));
            apdu.sendBytesLong(inBuf, (short) 0, (short) (cborEncoder.getCurrentOffset()-1));

        } catch (Exception e) {
            returnError(apdu, buffer, CTAP2_ERR_INVALID_CREDENTIAL);
        }
    }
    private void addResident(APDU apdu, byte[] buffer, StoredCredential cred) {
        // Add a Discoverable Credential (resident)
        try {
            discoverableCreds.addCredential(cred);
        } catch (ISOException e) {
            returnError(apdu, buffer, CTAP2_ERR_INVALID_CREDENTIAL);
        }
    }
    /**
     * Finds all credentials scoped to the RpId, and optionally the allowList, in assertion
     * @param apdu the APDU to send through for errors
     * @param buffer the APDU buffer
     * @param assertion the assertion CTAP object
     * @return an array of StoredCredential objects, null if none matched.
     */
    private StoredCredential[] findCredentials(APDU apdu, byte[] buffer, AuthenticatorGetAssertion assertion) {
        // TODO: Need to check for and enforce allow lists
        StoredCredential[] list = new StoredCredential[discoverableCreds.getLength()];
        StoredCredential temp;
        vars[6] = 0;
        for(vars[7] = 0; vars[7] < discoverableCreds.getLength(); vars[7]++) {
            temp = discoverableCreds.getCred(vars[7]);
            if(temp.rp.checkId(assertion.rpId, (short) 0, (short) assertion.rpId.length)) {
                // Then valid
                list[vars[6]++] = temp;
            }
        }
        // Trim the list
        StoredCredential[] ret = new StoredCredential[vars[6]];
        // One thing we need to do is reverse the array, because the newest cred should be first
        vars[5] = (short) (vars[6]-1);
        for(vars[7] = 0; vars[7] < vars[6]; vars[7]++) {
            ret[vars[7]] = list[vars[5]--];
        }
        // Null out the unused stuff
        list = null;
        temp = null;
        JCSystem.requestObjectDeletion();
        return ret;

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
