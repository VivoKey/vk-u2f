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

import javacard.security.Signature;

public class PublicKeyCredentialParams {
    // Stores an array consisting of wanted credentials for a AuthenticatorMakeCredential object
    // Provides conversion services to Java algorithms 
    private short[] paramList;
    private short listIndex;
    public static final short COSE_ES256 = -7;
    public static final short COSE_RS256 = -257;
    public static final short COSE_PS256 = -37;
    public PublicKeyCredentialParams(short len) {
        // Create the array
        paramList = new short[len];
        listIndex = 0;
    }
    // Add an algorithm 
    public void addAlgorithm(short algId) {
        // Add to the list as-is
        paramList[listIndex++] = algId;
    }
    // Return the first algorithm, in Java algorithm form, that we support from the list
    public byte getAlgorithm() {
        for(short i = 0; i < listIndex; i++) {
            if(paramList[i] == COSE_ES256) {
                return Signature.ALG_ECDSA_SHA_256;
            }
            if(paramList[i] == COSE_RS256) {
                return Signature.ALG_RSA_SHA_256_PKCS1;
            }
            if(paramList[i] == COSE_PS256) {
                return Signature.ALG_RSA_SHA_256_PKCS1_PSS;
            }
        }
        // Didn't get a result
        return 0;
    }
}
