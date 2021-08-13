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
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class StoredES256Credential extends StoredCredential {

    Signature sig;

    public StoredES256Credential(AuthenticatorMakeCredential inputData) {
        // Generate a new ES256 credential
        kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        KeyParams.sec256r1params((ECKey) kp.getPublic());
        kp.genKeyPair();
        user = inputData.getUser();
        rp = inputData.getRp();
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sig.init(kp.getPrivate(), Signature.MODE_SIGN);
        isResident = inputData.isResident();
        if(!isResident) {
            // Create non-resident format
            id = new byte[1];
        }
    }

    protected StoredES256Credential(byte[] dataArr, short dataOff, short dataLen) {
        // Format is dependent on the credential - this one is dirt simple.
        // Public key, as formatted for ANSI X9.62, and then private key, formatted
        // however it is formatted.

        // Create the keypair
        kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        // Set the keypair as sec256r1
        KeyParams.sec256r1params((ECKey) kp.getPublic());
        KeyParams.sec256r1params((ECKey) kp.getPrivate());
        // Load W
        ((ECPublicKey) kp.getPublic()).setW(dataArr, dataOff, (short) 97);
        // Load S
        ((ECPrivateKey) kp.getPrivate()).setS(dataArr, (short) (dataOff+97), (short) (dataLen - 97));
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
        // Depends on if we're a resident key or not
        if (isResident) {
            // AAGUID (16), 0010 (2), Credential ID (16), the map (1 byte header, 6 bytes
            // keytype and curve type, 35 bytes x, 35 bytes y, 77 total)
            return (short) 111;
        } else {
            // AAGUID (16), 00?? (2), Credential ID (??), the map (1 byte header, 6 bytes
            // keytype and curve type, 35 bytes x, 35 bytes y, 77 total)
            return (short) 111;
        }

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
        return new StoredES256Credential(scratch, (short) 0, len);
    }

}
