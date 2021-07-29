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
import javacard.framework.ISO7816;
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
    public AttestationKeyPair attestation;
    private byte[] info;
    private StoredCredential[] assertionCreds;
    private short[] nextAssertion;
    AuthenticatorGetAssertion assertion;
    private boolean persoComplete;
    private boolean[] isChaining;
    private short[] chainRam;
    private short[] outChainRam;
    private boolean[] isOutChaining;

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

    public static final byte FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL = (byte) 0x01;
    public static final byte FIDO2_AUTHENTICATOR_GET_ASSERTION = (byte) 0x02;
    public static final byte FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION = (byte) 0x08;
    public static final byte FIDO2_AUTHENTICATOR_GET_INFO = (byte) 0x04;
    public static final byte FIDO2_AUTHENTICATOR_CLIENT_PIN = (byte) 0x06;
    public static final byte FIDO2_AUTHENTICATOR_RESET = (byte) 0x07;
    // Vendor specific - for attestation cert loading.
    public static final byte FIDO2_VENDOR_ATTEST_SIGN = (byte) 0x41;
    public static final byte FIDO2_VENDOR_ATTEST_LOADCERT = (byte) 0x42;
    public static final byte FIDO2_VENDOR_PERSO_COMPLETE = (byte) 0x43;
    public static final byte FIDO2_VENDOR_ATTEST_GETPUB = (byte) 0x44;
    public static final byte FIDO2_VENDOR_ATTEST_GETCERT = (byte) 0x45;

    // AAGUID - this uniquely identifies the type of authenticator we have built.
    // If you're reusing this code, please generate your own GUID and put it here -
    // this is unique to manufacturer and device model.
    public static final byte[] aaguid = { (byte) 0xd7, (byte) 0xa4, (byte) 0x23, (byte) 0xad, (byte) 0x3e, (byte) 0x19,
            (byte) 0x44, (byte) 0x92, (byte) 0x92, (byte) 0x00, (byte) 0x78, (byte) 0x13, (byte) 0x7d, (byte) 0xcc,
            (byte) 0xc1, (byte) 0x36 };

    public CTAP2() {

        // 1200 bytes of a transient buffer for read-in and out
        try {
            inBuf = JCSystem.makeTransientByteArray((short) 1200, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            inBuf = new byte[1210];
        }
        try {
            scratch = JCSystem.makeTransientByteArray((short) 768, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            scratch = new byte[768];
        }
        vars = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        // Create the CBOR decoder
        cborDecoder = new CBORDecoder();
        cborEncoder = new CBOREncoder();
        discoverableCreds = new CredentialArray((short) 10);
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        attestation = new AttestationKeyPair();
        nextAssertion = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        persoComplete = false;
        isChaining = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        chainRam = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        outChainRam = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        isOutChaining = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
    }

    public void handle(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        vars[3] = doApduIngestion(apdu);
        if(vars[3] == 0) {
            // If zero, we had no ISO error, but there might be a CTAP error to return. Throw either way.
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
            return;
        }
        // TODO: Chaining responses
        // Need to grab the CTAP command byte
        switch (inBuf[0]) {
            case FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL:
                authMakeCredential(apdu, buffer, vars[3]);
                break;
            case FIDO2_AUTHENTICATOR_GET_ASSERTION:
                authGetAssertion(apdu, buffer, vars[3]);
                break;
            case FIDO2_AUTHENTICATOR_GET_INFO:
                authGetInfo(apdu);
                break;
            case FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION:
                authGetNextAssertion(apdu, buffer);
                break;
            case FIDO2_VENDOR_ATTEST_SIGN:
                attestSignRaw(apdu, buffer, vars[3]);
                break;
            case FIDO2_VENDOR_ATTEST_LOADCERT:
                attestSetCert(apdu, buffer, vars[3]);
                break;
            case FIDO2_VENDOR_PERSO_COMPLETE:
                persoComplete(apdu, buffer, vars[3]);
                break;
            case FIDO2_VENDOR_ATTEST_GETPUB:
                getAttestPublic(apdu, buffer, vars[3]);
                break;
            case FIDO2_VENDOR_ATTEST_GETCERT:
                getCert(apdu);
                break;
            default:
                returnError(apdu, buffer, CTAP1_ERR_INVALID_COMMAND);
        }

    }

    public void persoComplete(APDU apdu, byte[] buffer, short bufLen) {
        if (attestation.isCertSet() && !persoComplete) {
            persoComplete = true;
            returnError(apdu, buffer, CTAP1_ERR_SUCCESS);
        } else {
            returnError(apdu, buffer, CTAP1_ERR_INVALID_COMMAND);
        }
    }

    /**
     * Gets the attestation public key.
     * 
     * @param apdu
     * @param buffer
     * @param inBuf
     * @param bufLen
     */
    public void getAttestPublic(APDU apdu, byte[] buffer, short bufLen) {
        if (persoComplete) {
            returnError(apdu, buffer, CTAP1_ERR_INVALID_COMMAND);
            return;
        }
        inBuf[0] = 0x00;
        vars[0] = (short) (attestation.getPubkey(inBuf, (short) 1) + 1);
        apdu.setOutgoing();
        apdu.setOutgoingLength(vars[0]);
        apdu.sendBytesLong(inBuf, (short) 0, vars[0]);
    }

    /**
     * Performs raw signatures, may only occur when personalisation is not complete.
     * 
     * @param apdu
     * @param buffer
     * @param inBuf
     * @param bufLen
     */
    public void attestSignRaw(APDU apdu, byte[] buffer, short bufLen) {
        if (persoComplete) {
            returnError(apdu, buffer, CTAP1_ERR_INVALID_COMMAND);
        }
        Util.arrayCopy(inBuf, (short) 1, scratch, (short) 0, (short) (bufLen - 1));
        inBuf[0] = 0x00;
        vars[2] = attestation.sign(scratch, (short) 0, vars[1], inBuf, (short) 1);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (vars[2] + 1));
        apdu.sendBytesLong(inBuf, (short) 0, (short) (vars[2] + 1));
    }

    public void attestSetCert(APDU apdu, byte[] buffer, short bufLen) {
        if (persoComplete) {
            returnError(apdu, buffer, CTAP1_ERR_INVALID_COMMAND);
        }
        // We don't actually use any CBOR here, simplify copying
        attestation.setCert(inBuf, (short) 1, (short) (bufLen - 1));
        MessageDigest dig = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        short len = (short) (dig.doFinal(attestation.x509cert, (short) 0, attestation.x509len, inBuf, (short) 3) + 3);
        inBuf[0] = 0x00;
        Util.setShort(inBuf, (short) 1, attestation.x509len);
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(inBuf, (short) 0, len);
    }

    public void authMakeCredential(APDU apdu, byte[] buffer, short bufLen) {
        try {
            // Init the decoder
            cborDecoder.init(inBuf, (short) 1, bufLen);
            // create a credential object
            AuthenticatorMakeCredential cred = new AuthenticatorMakeCredential(cborDecoder);

            if (cred.isResident()) {
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
                cborEncoder.encodeTextString(Utf8Strings.UTF8_ATTSTMT, (short) 0, (short) 7);
                // First off create a byte array for the attestation packed array, as it can get
                // kinda big.
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
                // The signature is over the scratch data, first, but with the client data
                // appended
                vars[0] += cred.getDataHash(scratch, vars[0]);
                // Sign into the scratch buffer, but at vars[0] + 1
                vars[2] = attestation.sign(scratch, (short) 0, vars[0], scratch, (short) (vars[0] + 1));
                // Create a DER encoding, ffs
                scratch[(short) (vars[0] + vars[2] + 1)] = (byte) 0x30;
                // Skip the next one, as it's length of total data - we'll make vars[3] this
                vars[3] = 3;
                // This one's 0x02 which is integer type
                scratch[(short) (vars[0] + vars[2] + vars[3]++)] = (byte) 0x02;
                // This is length of r, the first half of the signature - it'll always be 32
                // bytes due to signatures being 64
                scratch[(short) (vars[0] + vars[2] + vars[3]++)] = (byte) 0x20;
                // Copy r in
                Util.arrayCopy(scratch, (short) (vars[0] + 1), scratch, scratch[(short) (vars[0] + vars[2] + vars[3])],
                        (short) 32);
                vars[3] += 32;
                // Set the type of s - integer
                scratch[(short) (vars[0] + vars[2] + vars[3]++)] = (byte) 0x02;
                // Set length of s - 32 bytes
                scratch[(short) (vars[0] + vars[2] + vars[3]++)] = (byte) 0x20;
                // Copy s in
                Util.arrayCopy(scratch, (short) (vars[0] + 33), scratch, scratch[(short) (vars[0] + vars[2] + vars[3])],
                        (short) 32);
                vars[3] += 32;
                // Set the length of the data
                scratch[(short) (vars[0] + vars[2] + 2)] = (byte) vars[3];
                // Set this into the encoder
                enc2.encodeByteString(scratch, scratch[(short) (vars[0] + vars[2] + 1)], (short) (vars[3] + 1));
                // Set the x509 now
                enc2.encodeTextString(Utf8Strings.UTF8_X5C, (short) 0, (short) 3);
                enc2.encodeByteString(attestation.x509cert, (short) 0, attestation.x509len);
                // Now set this whole array into the other CBOR
                cborEncoder.encodeByteString(packed, (short) 0,enc2.getCurrentOffset());
                // We're actually done, send this out
                sendLongChaining(apdu, cborEncoder.getCurrentOffset());
            }
        } catch (ISOException e) {
            // We redo ISOExceptions as a CBOR error
            returnError(apdu, buffer, CTAP2_ERR_INVALID_CBOR);
        }

    }

    public void authGetAssertion(APDU apdu, byte[] buffer, short bufLen) {
        try {
            // Decode the CBOR array for the assertion
            cborDecoder.init(inBuf, (short) 1, bufLen);
            assertion = new AuthenticatorGetAssertion(cborDecoder);
            // Match the assertion to the credential
            // Get a list of matching credentials
            assertionCreds = findCredentials(apdu, buffer, assertion);
            // Use the first one; this complies with both ideas - use the most recent match
            // if no allow list, use any if an allow list existed
            if (assertionCreds[0] == null) {
                returnError(apdu, buffer, CTAP2_ERR_NO_CREDENTIALS);
            }
            // Create the authenticatorData to sign
            sha.doFinal(assertion.rpId, (short) 0, (short) assertion.rpId.length, scratch, (short) 0);
            scratch[32] = 0x05;
            assertionCreds[0].readCounter(scratch, (short) 33);
            // Copy the hash in
            vars[2] = assertion.getHash(scratch, (short) 37);
            // Create the output

            // Status flags first
            inBuf[0] = 0x00;
            // Create the encoder
            cborEncoder.init(inBuf, (short) 1, (short) 1199);
            // Determine if we need 4 or 5 in the array
            if (assertionCreds.length > 1) {
                doAssertionCommon(cborEncoder, (short) 5);
            } else {
                doAssertionCommon(cborEncoder, (short) 4);
            }
            nextAssertion[0] = (short) 1;
            // Emit this as a response
            sendLongChaining(apdu, cborEncoder.getCurrentOffset());

        } catch (Exception e) {
            returnError(apdu, buffer, CTAP2_ERR_INVALID_CREDENTIAL);
        }
    }

    /**
     * Get the next assertion in a list of multiple.
     * 
     * @param apdu
     * @param buffer
     * @param inBuf
     * @param inLen
     */
    private void authGetNextAssertion(APDU apdu, byte[] buffer) {
        try {
            // Confirm that we have more assertions to do
            if (nextAssertion[0] != (short) 0 && nextAssertion[0] < assertionCreds.length) {
                // Create the authenticatorData to sign
                sha.doFinal(assertion.rpId, (short) 0, (short) assertion.rpId.length, scratch, (short) 0);
                scratch[32] = 0x05;
                assertionCreds[nextAssertion[0]].readCounter(scratch, (short) 33);
                // Copy the hash in
                vars[2] = assertion.getHash(scratch, (short) 37);
                // Create the output

                // Status flags first
                inBuf[0] = 0x00;
                // Create the encoder
                cborEncoder.init(inBuf, (short) 1, (short) 1199);
                doAssertionCommon(cborEncoder, (short) 4);

                nextAssertion[0]++;
                // Emit this as a response
                sendLongChaining(apdu, cborEncoder.getCurrentOffset());
            }
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
     * Finds all credentials scoped to the RpId, and optionally the allowList, in
     * assertion
     * 
     * @param apdu      the APDU to send through for errors
     * @param buffer    the APDU buffer
     * @param assertion the assertion CTAP object
     * @return an array of StoredCredential objects, null if none matched.
     */
    private StoredCredential[] findCredentials(APDU apdu, byte[] buffer, AuthenticatorGetAssertion assertion) {
        // TODO: Need to check for and enforce allow lists
        StoredCredential[] list = new StoredCredential[discoverableCreds.getLength()];
        StoredCredential temp;
        vars[6] = 0;
        for (vars[7] = 0; vars[7] < discoverableCreds.getLength(); vars[7]++) {
            temp = discoverableCreds.getCred(vars[7]);
            if (temp.rp.checkId(assertion.rpId, (short) 0, (short) assertion.rpId.length)) {
                // Then valid
                list[vars[6]++] = temp;
            }
        }
        // Trim the list
        StoredCredential[] ret = new StoredCredential[vars[6]];
        // One thing we need to do is reverse the array, because the newest cred should
        // be first
        vars[5] = (short) (vars[6] - 1);
        for (vars[7] = 0; vars[7] < vars[6]; vars[7]++) {
            ret[vars[7]] = list[vars[5]--];
        }
        // Null out the unused stuff
        list = null;
        temp = null;
        JCSystem.requestObjectDeletion();
        return ret;

    }

    /**
     * Return an error via APDU - an error on the FIDO2 side is considered a success
     * in APDU-land so we send a response.
     * 
     * @param apdu   shared APDU object
     * @param buffer APDU buffer
     * @param err    error code
     */
    public void returnError(APDU apdu, byte[] buffer, byte err) {
        buffer[0] = err;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    /**
     * Get authenticator-specific informtion, and return it to the platform.
     * 
     * @param apdu
     * @param buffer
     * @param inBuf
     * @param bufLen
     */
    public void authGetInfo(APDU apdu) {
        // Create the authenticator info if not present.
        if (info == null) {
            // Create the authGetInfo - 0x00 is success
            inBuf[0] = 0x00;
            cborEncoder.init(inBuf, (short) 1, (short) 1199);
            cborEncoder.startMap((short) 4);
            // 0x01, versions
            cborEncoder.encodeUInt8((byte) 0x01);
            // Value is an array of strings
            cborEncoder.startArray((short) 2);
            // Type 1, FIDO2
            cborEncoder.encodeTextString(Utf8Strings.UTF8_FIDO2, (short) 0, (short) 8);
            // Type 2, U2F
            cborEncoder.encodeTextString(Utf8Strings.UTF8_U2F, (short) 0, (short) 6);
            // AAGUID, 0x03
            cborEncoder.encodeUInt8((byte) 0x03);
            cborEncoder.encodeByteString(aaguid, (short) 0, (short) 16);
            // Options, 0x04
            cborEncoder.encodeUInt8((byte) 0x04);
            // Map of 3
            cborEncoder.startMap((short) 3);
            // Rk
            cborEncoder.encodeTextString(Utf8Strings.UTF8_RK, (short) 0, (short) 2);
            cborEncoder.encodeBoolean(true);
            // UP
            cborEncoder.encodeTextString(Utf8Strings.UTF8_UP, (short) 0, (short) 2);
            cborEncoder.encodeBoolean(true);
            // UV
            cborEncoder.encodeTextString(Utf8Strings.UTF8_UV, (short) 0, (short) 2);
            cborEncoder.encodeBoolean(true);
            // Max msg size, 0x05
            cborEncoder.encodeUInt8((byte) 0x05);
            cborEncoder.encodeUInt16((short) 1200);
            // Done
            JCSystem.beginTransaction();
            info = new byte[cborEncoder.getCurrentOffset()];
            Util.arrayCopy(inBuf, (short) 0, info, (short) 0, cborEncoder.getCurrentOffset());
            JCSystem.commitTransaction();
        }
        // Send it
        Util.arrayCopyNonAtomic(info, (short) 0, inBuf, (short) 0, (short)info.length);
        sendLongChaining(apdu, (short) info.length);
    }

    /**
     * Covers the common assertion building process.
     * 
     * @param enc
     * @param mapLen
     */
    private void doAssertionCommon(CBOREncoder enc, short mapLen) {

        // Determine if we need 4 or 5 in the array
        if (mapLen == 4) {
            enc.startMap((short) 4);
        } else {
            enc.startMap((short) 5);
        }

        // Tag 1, credential data
        enc.encodeUInt8((byte) 0x01);
        // Start a map, which is all the PublicKeyCredentialDescriptor is
        enc.startMap((short) 2);
        // Put the key for the type
        cborEncoder.encodeTextString(Utf8Strings.UTF8_TYPE, (short) 0, (short) 4);
        // Put the value
        cborEncoder.encodeTextString(Utf8Strings.UTF8_PUBLIC_KEY, (short) 0, (short) 10);
        // Put the id key
        cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
        // Put the value, which is a byte array
        cborEncoder.encodeByteString(assertionCreds[nextAssertion[0]].id, (short) 0,
                (short) assertionCreds[nextAssertion[0]].id.length);
        // Done with tag 1
        cborEncoder.encodeUInt8((byte) 0x02);
        // Tag 2, which is the Authenticator bindings data
        cborEncoder.encodeByteString(scratch, (short) 0, (short) (vars[2] + 36));
        // Tag 3, the signature of said data.
        // Sign the data
        vars[3] = assertionCreds[0].performSignature(scratch, (short) 0, (short) (vars[2] + 36), scratch,
                (short) (vars[2] + 37));
        // Put the tag in
        cborEncoder.encodeUInt8((byte) 0x03);
        // Put the data in
        cborEncoder.encodeByteString(scratch, (short) (vars[2] + 37), vars[3]);
        // Tag 4, user details
        cborEncoder.encodeUInt8((byte) 0x04);
        // Start the PublicKeyCredentialUserEntity map
        cborEncoder.startMap((short) 3);
        cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
        cborEncoder.encodeByteString(assertionCreds[nextAssertion[0]].user.id, (short) 0,
                (short) assertionCreds[nextAssertion[0]].user.id.length);
        // The displayName
        cborEncoder.encodeTextString(Utf8Strings.UTF8_DISPLAYNAME, (short) 0, (short) 11);
        cborEncoder.encodeTextString(assertionCreds[nextAssertion[0]].user.displayName.str, (short) 0,
                assertionCreds[nextAssertion[0]].user.displayName.len);
        // The name
        cborEncoder.encodeTextString(Utf8Strings.UTF8_NAME, (short) 0, (short) 4);
        cborEncoder.encodeTextString(assertionCreds[nextAssertion[0]].user.name.str, (short) 0,
                assertionCreds[nextAssertion[0]].user.name.len);
        // Done tag 4
        if (mapLen == 5) {
            cborEncoder.encodeUInt8((byte) 0x05);
            cborEncoder.encodeUInt8((byte) assertionCreds.length);
        }

    }

    // There's only so many ways to do this.
    static boolean isCommandChainingCLA(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        return ((byte)(buf[0] & (byte)0x10) == (byte)0x10);
    }

    /**
     * Handle the command chaining or extended APDU logic.
     * 
     * Due to the FIDO2 spec requiring support for both extended APDUs and command chaining, we need to implement chaining here.
     * 
     * I didn't want to pollute the logic over in the process function, and it makes sense to do both here.
     * @param apdu
     * @return length of data to be processed. 0 if command chaining's not finished.
     */
    private short doApduIngestion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Receive the APDU
        vars[4] = apdu.setIncomingAndReceive();
        // Get true incoming data length
        vars[3] = apdu.getIncomingLength();
        // Check if the APDU is too big, we only handle 1200 byte
        if (vars[3] > 1200) {
            returnError(apdu, buffer, CTAP2_ERR_REQUEST_TOO_LARGE);
            return 0;
        }
        // Check what we need to do re APDU buffer, is it full (special case for 1 len)

        // If this is a command chaining APDU, swap to that logic
        if(isCommandChainingCLA(apdu)) {
            // In the chaining
            if(!isChaining[0]) {
                // Must be first chaining APDU
                isChaining[0] = true;
                // Prep the variables
                chainRam[0] = 0;
            }
            // Copy buffer
            chainRam[1] = vars[4];
            // chainRam[0] is the current point in the buffer we start from
            chainRam[0] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), inBuf, chainRam[0], chainRam[1]);
            return 0x00;
        } else if (isChaining[0]) {
            // Must be the last of the chaining - make the copy and return the length.
            chainRam[1] = vars[4];
            chainRam[0] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), inBuf, chainRam[0], chainRam[1]);
            isChaining[0] = false;
            isChaining[1] = true;
            return chainRam[0];
        } else if (vars[3] == 0x01) {
            inBuf[0] = buffer[apdu.getOffsetCdata()];
            return 0x01;
        } else if (apdu.getCurrentState() == APDU.STATE_FULL_INCOMING) {
            // We need to do no more
            // Read the entirety of the buffer into the inBuf
            Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), inBuf, (short) 0, vars[3]);
            return vars[4];
        } else {
            // The APDU needs a multi-stage copy
            // First, copy the current data buffer in
            // Get the number of bytes in the data buffer that are the Lc, vars[5] will do
            vars[5] = vars[4];
            // Make the copy, vars[3] is bytes remaining to get
            vars[4] = 0;
            while (vars[3] > 0) {
                // Copy data
                vars[4] = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), inBuf, vars[4], vars[5]);
                // Decrement vars[3] by the bytes copied
                vars[3] -= vars[5];
                // Pull more bytes
                vars[5] = apdu.receiveBytes(apdu.getOffsetCdata());
            }
            // Now we're at the end, here, and the commands expect us to give them a data length. Turns out Le bytes aren't anywhere to be found here.
            // The commands use vars[3], so vars[4] will be fine to copy to vars[3].
            return vars[4];
        }

    }

    /**
     * Gets 256 or fewer bytes from inBuf.
     * @param apdu
     */
    public void getData(APDU apdu) {
        if(outChainRam[0] > 256) {
            // More to go after this
            outChainRam[0] -= 256;
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 256);
            apdu.sendBytesLong(inBuf, outChainRam[1], (short) 256);
            outChainRam[1] += 256;
            if(outChainRam[0] > 255) {
                // More than 255 (at least 256) to go, so 256 more
                ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
            } else {
                // Less than, so say how many bytes are left.
                ISOException.throwIt(Util.makeShort((byte) 0x61, (byte) outChainRam[0]));
            }
        } else {
            // This is the last message
            apdu.setOutgoing();
            apdu.setOutgoingLength(outChainRam[0]);
            apdu.sendBytesLong(inBuf, outChainRam[1], outChainRam[0]);
            isOutChaining[0] = false;
            outChainRam[0] = 0;
            outChainRam[1] = 0;
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
    }
    /**
     * Set chaining flags to send dataLen bytes from inLen via chaining, if necessary.
     * @param apdu
     */
    public void sendLongChaining(APDU apdu, short dataLen) {
        if(dataLen > 256) {
            // Set the chaining boolean to 1
            isOutChaining[0] = true;
            // All the bytes are in inBuf already
            // Set the chaining remainder to dataLen minus 255
            outChainRam[0] = (short) (dataLen - 256);
            // Send the first 255 bytes out
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 256);
            apdu.sendBytesLong(inBuf, (short) 0, (short) 256);
            outChainRam[1] = 256;
            // Throw the 61 xx
            if(outChainRam[0] > 255) {
                // More than 255 (at least 256) to go, so 256 more
                ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
            } else {
                // Less than, so say how many bytes are left.
                ISOException.throwIt(Util.makeShort((byte) 0x61, (byte) outChainRam[0]));
            }
        } else {
            // Chaining not necessary, send in one go
            isOutChaining[0] = false;
            apdu.setOutgoing();
            apdu.setOutgoingLength(dataLen);
            apdu.sendBytesLong(inBuf, (short) 0, dataLen);
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        

    }
    /**
     * Checks if chaining is set for U2FApplet
     * @return
     */
    public boolean isChaining() {
        return isOutChaining[0];
    }

    private void getCert(APDU apdu) {
        inBuf[0] = 0x00;
        vars[0] = (short)(attestation.getCert(inBuf, (short) 1)+1);
        sendLongChaining(apdu, vars[0]);
    }


}
