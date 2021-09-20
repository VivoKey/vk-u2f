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
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.UserException;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;

public class CTAP2 extends Applet implements ExtendedLength {

    private CBORDecoder cborDecoder;
    private CBOREncoder cborEncoder;

    private byte[] inBuf;
    private byte[] scratch;
    private short[] vars;
    private CredentialArray discoverableCreds;
    private MessageDigest sha;
    private AttestationKeyPair attestation;
    private byte[] info;
    private StoredCredential[] assertionCreds;
    private short[] nextAssertion;
    AuthenticatorGetAssertion assertion;
    private boolean persoComplete;
    private boolean[] isChaining;
    private short[] chainRam;
    private short[] outChainRam;
    private boolean[] isOutChaining;
    private AuthenticatorMakeCredential cred;

    private KeyPair ecDhKey;
    private boolean[] ecDhSet;

    private StoredCredential tempCred;

    private static final byte ISO_INS_GET_DATA = (byte) 0xC0;
    private static final byte FIDO2_INS_NFCCTAP_MSG = (byte) 0x10;

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
    public static final byte FIDO2_VENDOR_ATTEST_GETCERT = (byte) 0x4A;

    public static final byte FIDO2_DESELECT = 0x12;

    // AAGUID - this uniquely identifies the type of authenticator we have built.
    // If you're reusing this code, please generate your own GUID and put it here -
    // this is unique to manufacturer and device model.
    public static final byte[] aaguid = { (byte) 0xd7, (byte) 0xa4, (byte) 0x23, (byte) 0xad, (byte) 0x3e, (byte) 0x19,
            (byte) 0x44, (byte) 0x92, (byte) 0x92, (byte) 0x00, (byte) 0x78, (byte) 0x13, (byte) 0x7d, (byte) 0xcc,
            (byte) 0xc1, (byte) 0x36 };

    private CTAP2() {

        // 1210 bytes of a transient buffer for read-in and out
        // We advertise 1200 bytes supported, but 10 bytes for protocol nonsense
        try {
            inBuf = JCSystem.makeTransientByteArray((short) 1210, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            inBuf = new byte[1210];
        }
        try {
            scratch = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            scratch = new byte[512];
        }
        vars = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        // Create the CBOR decoder
        cborDecoder = new CBORDecoder();
        cborEncoder = new CBOREncoder();
        discoverableCreds = new CredentialArray((short) 5);
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        attestation = new AttestationKeyPair();
        nextAssertion = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        persoComplete = false;
        isChaining = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        chainRam = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        outChainRam = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        isOutChaining = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        ECPublicKey ecDhPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC,
                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        ECPrivateKey ecDhPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE,
                JCSystem.MEMORY_TYPE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
        ecDhKey = new KeyPair(ecDhPub, ecDhPriv);
        ecDhSet = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);

    }

    public void handle(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        tempCred = null;
        cred = null;
        vars[3] = doApduIngestion(apdu);
        if (vars[3] == 0) {
            // If zero, we had no ISO error, but there might be a CTAP error to return.
            // Throw either way.
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
            return;
        }
        // Need to grab the CTAP command byte
        switch (inBuf[0]) {
            case FIDO2_AUTHENTICATOR_MAKE_CREDENTIAL:
                authMakeCredential(apdu, vars[3]);
                break;
            case FIDO2_AUTHENTICATOR_GET_ASSERTION:
                authGetAssertion(apdu, vars[3]);
                break;
            case FIDO2_AUTHENTICATOR_GET_INFO:
                authGetInfo(apdu);
                break;
            case FIDO2_AUTHENTICATOR_GET_NEXT_ASSERTION:
                authGetNextAssertion(apdu, buffer);
                break;
            case FIDO2_VENDOR_ATTEST_SIGN:
                attestSignRaw(apdu, vars[3]);
                break;
            case FIDO2_VENDOR_ATTEST_LOADCERT:
                attestSetCert(apdu, vars[3]);
                break;
            case FIDO2_VENDOR_PERSO_COMPLETE:
                persoComplete(apdu);
                break;
            case FIDO2_VENDOR_ATTEST_GETPUB:
                getAttestPublic(apdu);
                break;
            case FIDO2_VENDOR_ATTEST_GETCERT:
                getCert(apdu);
                break;
            case FIDO2_AUTHENTICATOR_RESET:
                // Need to finish doing this, we can, i mean, but I don't like it
                doReset(apdu);
                break;
            default:
                returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
        }

    }

    public void persoComplete(APDU apdu) {
        if (attestation.isCertSet() && !persoComplete) {
            persoComplete = true;
            returnError(apdu, CTAP1_ERR_SUCCESS);
        } else {
            returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
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
    public void getAttestPublic(APDU apdu) {
        if (persoComplete) {
            returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
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
    public void attestSignRaw(APDU apdu, short bufLen) {
        if (persoComplete) {
            returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
            return;
        }
        Util.arrayCopy(inBuf, (short) 1, scratch, (short) 0, (short) (bufLen - 1));
        inBuf[0] = 0x00;
        vars[2] = attestation.sign(scratch, (short) 0, vars[1], inBuf, (short) 1);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (vars[2] + 1));
        apdu.sendBytesLong(inBuf, (short) 0, (short) (vars[2] + 1));
    }

    public void attestSetCert(APDU apdu, short bufLen) {
        if (persoComplete) {
            returnError(apdu, CTAP1_ERR_INVALID_COMMAND);
            return;
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

    public void authMakeCredential(APDU apdu, short bufLen) {
        // Init the decoder
        cborDecoder.init(inBuf, (short) 1, bufLen);
        // create a credential object
        try {
            cred = new AuthenticatorMakeCredential(cborDecoder);
        } catch (UserException e) {
            returnError(apdu, e.getReason());
            return;
        }

        // Create the actual credential
        switch (cred.getAlgorithm()) {
            case Signature.ALG_ECDSA_SHA_256:
                tempCred = new StoredES256Credential(cred);
                break;
            case Signature.ALG_RSA_SHA_256_PKCS1:
                tempCred = new StoredRS256Credential(cred);
                break;
            case Signature.ALG_RSA_SHA_256_PKCS1_PSS:
                tempCred = new StoredPS256Credential(cred);
                break;
            default:
                returnError(apdu, CTAP2_ERR_UNSUPPORTED_ALGORITHM);
                return;
        }
        if (cred.isResident()) {
            // Check if a credential exists on the exclude list

            if (cred.isExclude() && isPresent(cred.exclude)) {
                // Throw the error
                returnError(apdu, CTAP2_ERR_CREDENTIAL_EXCLUDED);
                return;
            }

            // Add the credential to the resident storage, overwriting if necessary
            addResident(apdu, tempCred);

            // Initialise the output buffer, for CBOR writing.
            // output buffer needs 0x00 as first byte as status code
            inBuf[0] = 0x00;
            cborEncoder.init(inBuf, (short) 1, (short) 1199);
            // Create a map in the buffer
            vars[0] = cborEncoder.startMap((short) 3);

            // Attestation stuff
            cborEncoder.writeRawByte((byte) 0x01);
            cborEncoder.encodeTextString(Utf8Strings.UTF8_PACKED, (short) 0, (short) 6);

            // Put the authdata identifier there
            cborEncoder.writeRawByte((byte) 0x02);
            // Allocate some space for the byte string
            vars[0] = cborEncoder.startByteString((short) (37 + tempCred.getAttestedLen()));
            // Stash where it begins
            vars[7] = vars[0];
            // Create the SHA256 hash of the RP ID
            tempCred.rp.getRp(scratch, (short) 0);
            vars[0] += sha.doFinal(scratch, (short) 0, tempCred.rp.getRpLen(), inBuf, vars[0]);
            // Set flags - User presence, user verified, attestation present
            inBuf[vars[0]++] = (byte) 0x45;
            // Set the signature counter
            vars[0] += tempCred.readCounter(inBuf, vars[0]);
            // Read the credential details in
            // Just note down where this starts for future ref
            vars[0] += tempCred.getAttestedData(inBuf, vars[0]);

            // Generate and then attach the attestation
            cborEncoder.writeRawByte((byte) 0x03);
            // Start to build into the cbor array manually, to avoid arrayCopy

            // Create a map with 3 things

            cborEncoder.startMap((short) 3);
            // Add the alg label
            cborEncoder.encodeTextString(Utf8Strings.UTF8_ALG, (short) 0, (short) 3);
            // Add the actual algorithm - -7 is 6 as a negative
            cborEncoder.encodeNegativeUInt8((byte) 0x06);
            // Add the actual signature, we should generate this
            cborEncoder.encodeTextString(Utf8Strings.UTF8_SIG, (short) 0, (short) 3);

            // Generate the signature, can't do this directly unfortunately.
            // We sign over the client data hash and the attested data.
            // AuthenticatorData is first. We noted down where it begins and know how long
            // it is.
            attestation.update(inBuf, vars[7], (short) (tempCred.getAttestedLen() + 37));
            // The client data hash is next, which we use to finish off the signature.
            vars[4] = attestation.sign(cred.dataHash, (short) 0, (short) cred.dataHash.length, scratch, (short) 0);
            // Create the byte string for the signature
            cborEncoder.encodeByteString(scratch, (short) 0, vars[4]);
            // Set the x509 cert now
            cborEncoder.encodeTextString(Utf8Strings.UTF8_X5C, (short) 0, (short) 3);
            // Supposedly we need an array here
            cborEncoder.startArray((short) 1);
            cborEncoder.encodeByteString(attestation.x509cert, (short) 0, attestation.x509len);
            // We're actually done, send this out
            sendLongChaining(apdu, cborEncoder.getCurrentOffset());

        } else {
            // Non-resident credential
            // TODO - we currently force resident credentials
            returnError(apdu, CTAP2_ERR_UNSUPPORTED_OPTION);
        }

    }

    public void authGetAssertion(APDU apdu, short bufLen) {
        nextAssertion[0] = (short) 0;
        // Decode the CBOR array for the assertion
        cborDecoder.init(inBuf, (short) 1, bufLen);
        try {
            assertion = new AuthenticatorGetAssertion(cborDecoder);
        } catch (UserException e) {
            returnError(apdu, e.getReason());
            return;
        }
        // Match the assertion to the credential
        // Get a list of matching credentials
        assertionCreds = findCredentials(apdu, assertion);
        // Use the first one; this complies with both ideas - use the most recent match
        // if no allow list, use any if an allow list existed
        if (assertionCreds.length == 0 || assertionCreds[0] == null) {
            returnError(apdu, CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
        // Create the authenticatorData to sign
        sha.doFinal(assertion.rpId, (short) 0, (short) assertion.rpId.length, scratch, (short) 0);
        if (assertion.options[1]) {
            scratch[32] = 0x05;
        } else {
            scratch[32] = 0x01;
        }

        assertionCreds[0].readCounter(scratch, (short) 33);
        // Copy the hash in
        assertion.getHash(scratch, (short) 37);
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
        // Confirm that we have more assertions to do
        if (nextAssertion[0] != (short) 0 && nextAssertion[0] < assertionCreds.length) {
            // Create the authenticatorData to sign
            sha.doFinal(assertion.rpId, (short) 0, (short) assertion.rpId.length, scratch, (short) 0);
            if (assertion.options[1]) {
                scratch[32] = 0x05;
            } else {
                scratch[32] = 0x01;
            }
            assertionCreds[nextAssertion[0]].readCounter(scratch, (short) 33);
            // Copy the hash in
            assertion.getHash(scratch, (short) 37);
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
    }

    // Process the AuthenticatorClientPin feature
    // Note: we only implement the keyAgreement bit
    public void clientPin(APDU apdu, short bufLen) {
        try {
            cborDecoder.init(inBuf, (short) 1, bufLen);
            // Start reading
            cborDecoder.readMajorType(CBORBase.TYPE_MAP);
            // Read PIN protocol tag
            if (cborDecoder.readInt8() != (byte) 0x01) {
                UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                return;
            }
            // Read the actual protocol
            if (cborDecoder.readInt8() != (byte) 0x01) {
                UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                return;
            }
            // Subcommand now
            if (cborDecoder.readInt8() != (byte) 0x02) {
                UserException.throwIt(CTAP2_ERR_INVALID_CBOR);
                return;
            }
            // Actual subcommand
            switch (cborDecoder.readInt8()) {
                case 0x02:
                    // Seems to be a Diffie-Hellman thing
                    generateDH(apdu);
                    break;
                default:
                    UserException.throwIt(CTAP2_ERR_UNSUPPORTED_OPTION);
                    return;
            }
        } catch (UserException e) {
            returnError(apdu, e.getReason());
        }
    }

    private void addResident(APDU apdu, StoredCredential cred) {
        // Add a Discoverable Credential (resident)
        try {
            discoverableCreds.addCredential(cred);
        } catch (UserException e) {
            returnError(apdu, e.getReason());
        }
    }

    // Generate a session-specific ECDH P-256 key for Diffie-Hellman with the
    // platform (Used for PIN but we only ever do it for hmac-secret)
    private void generateDH(APDU apdu) {
        byte[] w;
        try {
            w = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            w = new byte[65];
        }

        

        if (!ecDhSet[0]) {
            // Grab the public key and set it's parameters
            KeyParams.sec256r1params((ECKey) ecDhKey.getPublic());
            // Generate a new key-pair
            ecDhKey.genKeyPair();
        }

        ((ECPublicKey) ecDhKey.getPublic()).getW(w, (short) 0);
        // Return the data requested
        inBuf[0] = 0x00;
        cborEncoder.init(inBuf, (short) 1, (short) 1199);
        // Start a map
        cborEncoder.startMap((short) 1);
        // Encode the COSE key identifier
        cborEncoder.encodeUInt8((byte) 0x01);
        // Start the COSE map
        cborEncoder.startMap((short) 5);
        // Kty tag
        cborEncoder.encodeUInt8((byte) 0x01);
        // Kty value - EC2
        cborEncoder.encodeUInt8((byte) 0x02);
        // Alg tag
        cborEncoder.encodeUInt8((byte) 0x03);
        // Alg value - ES256 (-7, 6 in negative format) 
        cborEncoder.encodeNegativeUInt8((byte) 0x06);
        // Crv tag - negative
        cborEncoder.encodeNegativeUInt8((byte) 0x00);
        // Crv value - P-256
        cborEncoder.encodeUInt8((byte) 0x01);
        // X-coord tag
        cborEncoder.encodeNegativeUInt8((byte) 0x01);
        // X-coord value
        cborEncoder.encodeByteString(w, (short) 1, (short) 32);
        // Y-coord tag
        cborEncoder.encodeNegativeUInt8((byte) 0x02);
        // Y-coord value
        cborEncoder.encodeByteString(w, (short) 33, (short) 32);
        // That's it
        sendLongChaining(apdu, cborEncoder.getCurrentOffset());
    }   

    /**
     * Finds all credentials scoped to the RpId, and optionally the allowList, in
     * assertion
     * 
     * @param apdu      the APDU to send through for errors
     * @param assertion the assertion CTAP object
     * @return an array of StoredCredential objects, null if none matched.
     */
    private StoredCredential[] findCredentials(APDU apdu, AuthenticatorGetAssertion assertion) {
        StoredCredential[] list;
        StoredCredential temp;
        if (assertion.hasAllow()) {
            // Our list can be no bigger than the allowList
            list = new StoredCredential[(short) assertion.allow.length];

            vars[6] = 0;
            for (vars[7] = (short) (discoverableCreds.getLength() - 1); vars[7] >= 0; vars[7]--) {
                temp = discoverableCreds.getCred(vars[7]);
                // Check if null or doesn't match rpId
                if (temp != null && temp.rp.checkId(assertion.rpId, (short) 0, (short) assertion.rpId.length)) {
                    for (vars[5] = 0; vars[5] < (short) assertion.allow.length; vars[5]++) {
                        // Check the list
                        // Does length match?
                        if ((short) assertion.allow[vars[5]].id.length != (short) temp.id.length) {
                            continue;
                        }
                        if (Util.arrayCompare(assertion.allow[vars[5]].id, (short) 0, temp.id, (short) 0,
                                (short) temp.id.length) == 0) {
                            // Add it to the list
                            list[vars[6]++] = temp;
                        }

                    }
                }

            }

        } else {
            // Old code path, works fine for me
            list = new StoredCredential[discoverableCreds.getLength()];
            vars[6] = 0;
            for (vars[7] = (short) (discoverableCreds.getLength() - 1); vars[7] >= 0; vars[7]--) {
                temp = discoverableCreds.getCred(vars[7]);
                // Check for null or doesn't match rpId
                if (temp != null && temp.rp.checkId(assertion.rpId, (short) 0, (short) assertion.rpId.length)) {
                    // Then valid
                    list[vars[6]++] = temp;
                }
            }
        }

        // Trim the list
        StoredCredential[] ret = new StoredCredential[vars[6]];
        // Trim
        for (vars[7] = 0; vars[7] < vars[6]; vars[7]++) {
            ret[vars[7]] = list[vars[7]];
        }
        // Null out the unused stuff
        JCSystem.requestObjectDeletion();
        return ret;

    }

    /**
     * Check if anything in the list is present
     * 
     * @param list
     * @return
     */
    private boolean isPresent(PublicKeyCredentialDescriptor[] list) {
        StoredCredential temp;
        for (vars[7] = (short) 0; vars[7] < discoverableCreds.getLength(); vars[7]++) {
            temp = discoverableCreds.getCred(vars[7]);
            if (temp == null) {
                continue;
            }
            for (vars[6] = (short) 0; vars[6] < (short) list.length; vars[6]++) {
                if (temp.checkId(list[vars[6]].id, (short) 0, (short) list[vars[6]].id.length)) {
                    return true;
                }
            }

        }
        return false;
    }

    /**
     * Reset the authenticator. This doesn't actually take much. TODO: Implement
     * checking. This is just so testing doesn't crap out.
     */
    private void doReset(APDU apdu) {
        discoverableCreds = new CredentialArray((short) 5);
        JCSystem.requestObjectDeletion();
        returnError(apdu, CTAP1_ERR_SUCCESS);
    }

    /**
     * Return an error via APDU - an error on the FIDO2 side is considered a success
     * in APDU-land so we send a response.
     * 
     * @param apdu   shared APDU object
     * @param buffer APDU buffer
     * @param err    error code
     */
    public void returnError(APDU apdu, byte err) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = err;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    /**
     * Return an error via APDU - an error on the FIDO2 side is considered a success
     * in APDU-land so we send a response.
     * 
     * @param apdu   shared APDU object
     * @param buffer APDU buffer
     * @param err    error code
     */
    public void returnError(APDU apdu, short err) {
        byte[] buffer = apdu.getBuffer();
        // Get the low byte of the error.
        Util.setShort(buffer, (short) 0, err);
        apdu.setOutgoingAndSend((short) 1, (short) 1);
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
            cborEncoder.startArray((short) 1);
            // Type 1, FIDO2
            cborEncoder.encodeTextString(Utf8Strings.UTF8_FIDO2, (short) 0, (short) 8);
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
        Util.arrayCopyNonAtomic(info, (short) 0, inBuf, (short) 0, (short) info.length);
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
        // Put the id key
        cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
        // Put the value, which is a byte array
        cborEncoder.encodeByteString(assertionCreds[nextAssertion[0]].id, (short) 0,
                (short) assertionCreds[nextAssertion[0]].id.length);
        // Put the key for the type
        cborEncoder.encodeTextString(Utf8Strings.UTF8_TYPE, (short) 0, (short) 4);
        // Put the value
        cborEncoder.encodeTextString(Utf8Strings.UTF8_PUBLIC_KEY, (short) 0, (short) 10);
        // Done with tag 1
        cborEncoder.encodeUInt8((byte) 0x02);
        // Tag 2, which is the Authenticator bindings data (turns out this is excluding
        // the clientDataHash)
        cborEncoder.encodeByteString(scratch, (short) 0, (short) 37);
        // Tag 3, the signature of said data
        // Put the tag in
        cborEncoder.encodeUInt8((byte) 0x03);
        // Turns out this is DER encoding, again

        // Sign the data
        vars[3] = assertionCreds[nextAssertion[0]].performSignature(scratch, (short) 0, (short) 69, scratch,
                (short) 69);
        // Create the ByteString to put it into
        cborEncoder.encodeByteString(scratch, (short) 69, vars[3]);
        // Tag 4, user details
        cborEncoder.encodeUInt8((byte) 0x04);
        // Start the PublicKeyCredentialUserEntity map

        // If we have "UV" enabled, then we do all the info we have.
        if (assertion.options[1]) {
            cborEncoder.startMap(assertionCreds[nextAssertion[0]].user.numData);
            // We need to check what we have for users
            // Iterate over the bit flags
            boolean[] usrFlags = assertionCreds[nextAssertion[0]].getPresentUser();
            // This actually
            if (usrFlags[2]) {
                // Has the 'displayName' tag
                cborEncoder.encodeTextString(Utf8Strings.UTF8_DISPLAYNAME, (short) 0, (short) 11);
                cborEncoder.encodeTextString(assertionCreds[nextAssertion[0]].user.displayName.str, (short) 0,
                        assertionCreds[nextAssertion[0]].user.displayName.len);
            }
            if (usrFlags[1]) {
                // The 'id' tag
                cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
                cborEncoder.encodeByteString(assertionCreds[nextAssertion[0]].user.id, (short) 0,
                        (short) assertionCreds[nextAssertion[0]].user.id.length);
            }
            if (usrFlags[0]) {
                // The 'name'
                cborEncoder.encodeTextString(Utf8Strings.UTF8_NAME, (short) 0, (short) 4);
                cborEncoder.encodeTextString(assertionCreds[nextAssertion[0]].user.name.str, (short) 0,
                        assertionCreds[nextAssertion[0]].user.name.len);
            }
            if (usrFlags[3]) {
                // Has the 'icon' tag
                cborEncoder.encodeTextString(Utf8Strings.UTF8_ICON, (short) 0, (short) 4);
                cborEncoder.encodeTextString(assertionCreds[nextAssertion[0]].user.icon, (short) 0,
                        (short) assertionCreds[nextAssertion[0]].user.icon.length);
            }
        } else {
            // UV not enabled. Don't send extra info apart from the id field
            cborEncoder.startMap((short) 1);
            cborEncoder.encodeTextString(Utf8Strings.UTF8_ID, (short) 0, (short) 2);
            cborEncoder.encodeByteString(assertionCreds[nextAssertion[0]].user.id, (short) 0,
                    (short) assertionCreds[nextAssertion[0]].user.id.length);
        }

        // Done tag 4
        if (mapLen == 5) {
            cborEncoder.encodeUInt8((byte) 0x05);
            cborEncoder.encodeUInt8((byte) assertionCreds.length);
        }

    }

    // There's only so many ways to do this.
    static boolean isCommandChainingCLA(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        return ((byte) (buf[0] & (byte) 0x10) == (byte) 0x10);
    }

    /**
     * Handle the command chaining or extended APDU logic.
     * 
     * Due to the FIDO2 spec requiring support for both extended APDUs and command
     * chaining, we need to implement chaining here.
     * 
     * I didn't want to pollute the logic over in the process function, and it makes
     * sense to do both here.
     * 
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
            returnError(apdu, CTAP2_ERR_REQUEST_TOO_LARGE);
            return 0;
        }
        // Check what we need to do re APDU buffer, is it full (special case for 1 len)

        // If this is a command chaining APDU, swap to that logic
        if (isCommandChainingCLA(apdu)) {
            // In the chaining
            if (!isChaining[0]) {
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
            // Now we're at the end, here, and the commands expect us to give them a data
            // length. Turns out Le bytes aren't anywhere to be found here.
            // The commands use vars[3], so vars[4] will be fine to copy to vars[3].
            return vars[4];
        }

    }

    /**
     * Gets 256 or fewer bytes from inBuf.
     * 
     * @param apdu
     */
    public void getData(APDU apdu) {
        if (outChainRam[0] > 256) {
            // More to go after this
            outChainRam[0] -= 256;
            byte[] buf = apdu.getBuffer();
            Util.arrayCopyNonAtomic(inBuf, outChainRam[1], buf, (short) 0, (short) 256);
            apdu.setOutgoingAndSend((short) 0, (short) 256);
            outChainRam[1] += 256;
            if (outChainRam[0] > 255) {
                // At least 256 to go, so 256 more
                ISOException.throwIt((short) 0x6100);
            } else {
                // Less than, so say how many bytes are left.
                ISOException.throwIt(Util.makeShort((byte) 0x61, (byte) outChainRam[0]));
            }
        } else {
            // This is the last message
            byte[] buf = apdu.getBuffer();
            Util.arrayCopyNonAtomic(inBuf, outChainRam[1], buf, (short) 0, outChainRam[0]);
            apdu.setOutgoingAndSend((short) 0, outChainRam[0]);
            isOutChaining[0] = false;
            outChainRam[0] = 0;
            outChainRam[1] = 0;
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
    }

    /**
     * Set chaining flags to send dataLen bytes from inLen via chaining, if
     * necessary.
     * 
     * @param apdu
     */
    public void sendLongChaining(APDU apdu, short dataLen) {
        if (dataLen > 256) {
            // Set the chaining boolean to 1
            isOutChaining[0] = true;
            // All the bytes are in inBuf already
            // Set the chaining remainder to dataLen minus 256
            outChainRam[0] = (short) (dataLen - 256);
            // Send the first 256 bytes out
            byte[] buf = apdu.getBuffer();
            Util.arrayCopyNonAtomic(inBuf, (short) 0, buf, (short) 0, (short) 256);
            apdu.setOutgoingAndSend((short) 0, (short) 256);
            outChainRam[1] = 256;
            // Throw the 61 xx
            if (outChainRam[0] > 255) {
                // More than 255 (at least 256) to go, so 256 more
                ISOException.throwIt((short) 0x6100);
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
     * 
     * @return
     */
    public boolean isChaining() {
        return isOutChaining[0];
    }

    private void getCert(APDU apdu) {
        inBuf[0] = 0x00;
        vars[0] = (short) (attestation.getCert(inBuf, (short) 1) + 1);
        sendLongChaining(apdu, vars[0]);
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            Util.arrayCopyNonAtomic(Utf8Strings.UTF8_FIDO2, (short) 0, buffer, (short) 0,
                    (short) Utf8Strings.UTF8_FIDO2.length);
            apdu.setOutgoingAndSend((short) 0, (short) Utf8Strings.UTF8_FIDO2.length);
            return;
        }

        if (!apdu.isCommandChainingCLA() && apdu.isISOInterindustryCLA()) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        JCSystem.requestObjectDeletion();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case ISO_INS_GET_DATA:
                if (isChaining()) {
                    getData(apdu);
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                break;
            case FIDO2_INS_NFCCTAP_MSG:
                handle(apdu);
                break;
            case FIDO2_DESELECT:
                // Appears to be a reset function in the FIDO2 spec, but never referenced
                // anywhere
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short) (bArray[offset] + 1); // instance
        offset += (short) (bArray[offset] + 1); // privileges
        final CTAP2 applet = new CTAP2();
        try {
            applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        } catch (Exception e) {
            applet.register();
        }

    }

}
