package com.vivokey.u2f;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Dynamically resizable credential storage array. Gracefully handles space errors.
 */
public class CredentialArray {
    private StoredCredential[] creds;
    private boolean[] slotStatus;
    private short size;

    /**
     * Constructor for a CredentialArray.
     * @param initialSize Initial sizing for the CredentialArray.
     */
    public CredentialArray(short initialSize) {
        creds = new StoredCredential[initialSize];
        slotStatus = new boolean[initialSize];
        size = initialSize;
    }
    /**
     * Adds a new credential to the first free slot.
     * @param in the StoredCredential object to be stored.
     */
    public void addCredential(StoredCredential in) {
        try {
            // Find the first free slot
            for(short i = 0; i < size; i++) {
                if(!slotStatus[i]) {
                    // This slot is free
                    creds[i] = in;
                    slotStatus[i] = true;
                    return;
                } 
            }
            // No free slots, so expand
            StoredCredential[] tmp = new StoredCredential[size];
            for(short i = 0; i < size; i++) {
                // SonarLint throws an error here, but JavaCard can only copy byte arrays
                tmp[i] = creds[i];
            }
            creds = new StoredCredential[size*2];
            for(short i = 0; i < size; i++) {
                creds[i] = tmp[i];
            }
            tmp = null;
            // Delete objects we used to copy
            JCSystem.requestObjectDeletion();
        } catch (Exception e) {
            CTAP2Exception.throwIt(CTAP2.CTAP2_ERR_KEY_STORE_FULL);
        }
    }

    
}
