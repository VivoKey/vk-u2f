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
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;
import javacard.security.RSAPublicKey;

public class StoredRS256Credential extends StoredCredential {
    Cipher kpSignature;

    public StoredRS256Credential(AuthenticatorMakeCredential inputData) {
        // Generate a new RS256 credential
        kp = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
        kp.genKeyPair();
        user = inputData.getUser();
        rp = inputData.getRp();
    }

    private void finaliseInit() {
        // Generate a signature object
        kpSignature = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        kpSignature.init(kp.getPrivate(), Cipher.MODE_ENCRYPT);
    }

    @Override
    public short performSignature(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        if (!initialised) {
            finaliseInit();
        }
        incrementCounter();
        // Increment sig counter first
        return kpSignature.doFinal(inBuf, inOff, inLen, outBuf, outOff);

    }

    @Override
    public short getAttestedLen() {
        // AAGUID (16), 0010 (2), Credential ID (16), map (1 byte header + 6 bytes type
        // and alg + 260 bytes mod inc header, 5 bytes exp inc header)
        return (short) 306;
    }

    @Override
    public short getAttestedData(byte[] buf, short off) {
        CBOREncoder enc = new CBOREncoder();
        // Get the RSAPublicKey
        byte[] mod;
        byte[] exp;
        try {
            mod = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            mod = new byte[256];
        }
        try {
            exp = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_RESET);
        } catch (Exception e) {
            exp = new byte[3];
        }
        doAttestationCommon(buf, off);
        ((RSAPublicKey) kp.getPublic()).getModulus(mod, (short) 0);
        ((RSAPublicKey) kp.getPublic()).getExponent(exp, (short) 0);
        short len = 34;
        // Start the public key CBOR
        enc.init(buf, (short) (off + 34), (short) 1000);
        enc.startMap((short) 5);
        len++;
        // kty - key type
        len += enc.writeRawByte((byte) 0x01);
        // RSA
        len += enc.encodeUInt8((byte) 0x03);
        // alg
        len += enc.writeRawByte((byte) 0x03);
        // RS256 - -257 is 256 negative (minus 1 for neg on CBOR)
        len += enc.encodeNegativeUInt16((short) 256);
        // Modulus tag
        len += enc.encodeNegativeUInt8((byte) 0x00);
        // Write the modulus
        len += enc.encodeByteString(mod, (short) 0, (short) 256);
        // Exponent tag
        len += enc.encodeNegativeUInt8((byte) 0x01);
        // Write the exponent
        len += enc.encodeByteString(exp, (short) 0, (short) 3);
        return len;
    }

}
