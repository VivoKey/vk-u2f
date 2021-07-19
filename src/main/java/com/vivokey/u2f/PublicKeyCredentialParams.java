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
