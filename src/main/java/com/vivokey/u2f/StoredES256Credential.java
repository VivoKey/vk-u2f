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
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class StoredES256Credential extends StoredCredential {

    Signature sig;

    public StoredES256Credential(AuthenticatorMakeCredential inputData) {
        super();
        // Generate a new ES256 credential
        kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        KeyParams.sec256r1params((ECKey) kp.getPublic());
        kp.genKeyPair();
        user = inputData.getUser();
        rp = inputData.getRp();
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sig.init(kp.getPrivate(), Signature.MODE_SIGN);
        isResident = inputData.isResident();
        if (!isResident) {
            // Create non-resident format
            // Internal representation: 65 bytes for public key, 32 bytes for private
            // 128 bytes once padded, plus 16 more for IV so 144 byte ID
            id = new byte[144];
            // Use credScratch for making an internal representation
            byte[] scratch = ServerKeyCrypto.getCredScratch();
            // Copy W
            short len = ((ECPublicKey) kp.getPublic()).getW(scratch, (short) 0);
            len += ((ECPrivateKey) kp.getPrivate()).getS(scratch, (short) 65);
            ServerKeyCrypto.encryptData(scratch, (short) 0, len, id, (short) 0);
        }
    }

    protected StoredES256Credential(byte[] dataArr, short dataOff, short dataLen, byte[] inBuf, short inOff,
            short inLen) {
        // Format is dependent on the credential - this one is dirt simple.
        // Public key, as formatted for ANSI X9.62, and then private key, formatted
        // however it is formatted.
        super(dataArr, dataOff, dataLen, inBuf, inOff, inLen);
        // Create the keypair
        kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        // Set the keypair as sec256r1
        KeyParams.sec256r1params((ECKey) kp.getPublic());
        KeyParams.sec256r1params((ECKey) kp.getPrivate());
        // Load W
        ((ECPublicKey) kp.getPublic()).setW(dataArr, dataOff, (short) 65);
        // Load S
        ((ECPrivateKey) kp.getPrivate()).setS(dataArr, (short) (dataOff + 65), (short) (dataLen - 65));
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sig.init(kp.getPrivate(), Signature.MODE_SIGN);
        isResident = false;

    }

    @Override
    public short performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // Performs the signature as per ES256
        incrementCounter();
        return sig.sign(inBuf, inOff, inLen, outBuf, outOff);

    }

    @Override
    public short getAttestedLen() {
        // Turns out just calculate it on the fly
        // AAGUID (16), len (2), Credential ID (variable), the map (1 byte header, 6 bytes
        // keytype and curve type, 35 bytes x, 35 bytes y, 77 total)
        return (short) (16 + 2 + id.length + 77);

    }

    @Override
    public short getAttestedData(byte[] buf, short off) {
        CBOREncoder enc = new CBOREncoder();
        // Get the ECPublicKey
        byte[] w;
        try {
            w = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            w = new byte[65];
        }

        ((ECPublicKey) kp.getPublic()).getW(w, (short) 0);
        // Form the common params
        doAttestationCommon(buf, off);
        enc.init(buf, (short) (off + 34), (short) 1000);
        enc.startMap((short) 5);
        // We had to kinda hack the map labels - this is kty
        enc.writeRawByte((byte) 0x01);
        // value: EC2 keytype
        enc.encodeUInt8((byte) 0x02);
        // Alg - ES256
        enc.writeRawByte((byte) 0x03);
        enc.encodeNegativeUInt8((byte) 0x06);
        // Curve type - P256
        enc.encodeNegativeUInt8((byte) 0x00);
        enc.encodeUInt8((byte) 0x01);
        // X coord
        enc.encodeNegativeUInt8((byte) 0x01);
        enc.encodeByteString(w, (short) 1, (short) 32);
        // Y coord
        enc.encodeNegativeUInt8((byte) 0x02);
        enc.encodeByteString(w, (short) 33, (short) 32);
        // That is all
        w = null;
        JCSystem.requestObjectDeletion();
        return 111;
    }

    @Override
    public StoredES256Credential createSRCredential(byte[] inBuf, short inOff, short inLen) {
        // Decrypt the credential into scratch provided by ServerKeyCrypto
        byte[] scratch = ServerKeyCrypto.getCredScratch();
        short len = ServerKeyCrypto.decryptData(inBuf, inOff, inLen, scratch, (short) 0);
        // Pass over to the constructor
        return new StoredES256Credential(scratch, (short) 0, len, inBuf, inOff, inLen);
    }

}
