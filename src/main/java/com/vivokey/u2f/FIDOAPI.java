/*
*******************************************************************************
*   FIDO U2F Authenticator
*   (c) 2015 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*******************************************************************************
*/

package com.ledger.u2f;

import javacard.security.ECPrivateKey;

public interface FIDOAPI {

    /**
     * Generates a credential tied to this authenticator.
     *
     * @param applicationParameter Input buffer containing the 32-byte applicaiton parameter.
     * @param applicationParameterOffset The offset into applicationParameter at which
     *                                   the application parameter starts.
     * @param publicKey Output buffer that will hold the generated 65 byte public key.
     * @param publicKeyOffset Where in publicKey to start writing.
     * @param keyHandle Output buffer that will hold the generated key handle.
     * @param keyHandleOffset Where in keyHandle to start writing.
     * @param info A byte of information that can be recovered when the key handle is
     *             unwrapped. This is typically used for authenticators with multiple
     *             counters.
     * @return The length of the generated key handle.
     */
    short generateKeyAndWrap(byte[] applicationParameter, short applicationParameterOffset, byte[] publicKey, short publicKeyOffset, byte[] keyHandle, short keyHandleOffset, byte info);

    /**
     * Unwraps a previously generated key handle into a private key
     * and info byte.
     *
     * @param keyHandle Input buffer containing the key handle.
     * @param keyHandleOffset Offset into buffer where the key
     *                        handle starts.
     * @param keyHandleLength The length of the key handle.
     * @param applicationParameter Input buffer containing the
     *                             32-byte applicaiton parameter.
     * @param applicationParameterOffset Offset into buffer where the
     *                                   applicaiton parameter starts.
     * @param unwrappedPrivateKey ECPrivateKey instance to insert unwrapped
     *                            private key into.
     * @return The value of the "info" byte from generateKeyAndWrap()
     * @throws javacard.framework.ISOException ISO7816.SW_WRONG_DATA if the
     *         key handle doesn't match this applicaiton parameter or doesn't
     *         belong to this authenticator.
     */
    byte unwrap(byte[] keyHandle, short keyHandleOffset, short keyHandleLength, byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey unwrappedPrivateKey);

}
