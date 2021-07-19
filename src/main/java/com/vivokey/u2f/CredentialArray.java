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

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/**
 * Dynamically resizable credential storage array. Gracefully handles space errors.
 */
public class CredentialArray {
    private StoredCredential[] creds;
    private boolean[] slotStatus;
    private short size;
    private short counter;

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
     * Adds a new credential to the first free slot, or overwrites if a matching rp and user id matches.
     * @param in the StoredCredential object to be stored.
     */
    public void addCredential(StoredCredential in) {
        try {
            short slot = alreadyExists(in);
            creds[slot] = in;
            slotStatus[slot] = true;
        } catch (Exception e) {
            ISOException.throwIt(CTAP2.CTAP2_ERR_KEY_STORE_FULL);
        }
    }
    /**
     * Finds and returns a StoredCredential given the rpId and userId, returns null if not present.
     * @param rpId
     * @param off
     * @param len
     * @return
     */
    public StoredCredential getCredential(byte[] rpId, short rpOff, short rpLen, byte[] userId, short userOff, short userLen) {
        for(counter = 0; counter < size; counter++) {
            // Check the slot status, if the RP matches, and then if the user matches. If so, return the credential.
            if(slotStatus[counter] && creds[counter].rp.checkId(rpId, rpOff, rpLen) && creds[counter].user.checkId(userId, userOff, userLen)) {
                return creds[counter];
            }
        }
        return null;
    }
    /**
     * Confirms there is no already existing discoverable credential - if it finds one, it returns its location for overwriting.
     * @return the location of a discoverable credential already matching the RP and User IDs, or the first free slot otherwise.
     */
    public short alreadyExists(StoredCredential cred) {
        for(counter = 0; counter < size; counter++) {
            // Check the slot status, if the RP matches, and then if the user matches. If so, return the slot to use.
            if(slotStatus[counter] && creds[counter].rp.checkId(cred.rp) && creds[counter].user.checkId(cred.user)) {
                return counter;
            }
        }
        // Find the first free slot
        for(counter = 0; counter < size; counter++) {
            if(!slotStatus[counter]) {
                return counter;
            } 
        }
        // No free slots, so expand
        StoredCredential[] tmp = new StoredCredential[size];
        boolean[] tmpStatus = new boolean[size];
        for(counter = 0; counter < size; counter++) {
            // SonarLint throws an error here, but JavaCard can only copy byte arrays
            tmp[counter] = creds[counter];
            tmpStatus[counter] = slotStatus[counter];
        }
        creds = new StoredCredential[(short) (size*2)];
        slotStatus = new boolean[(short) (size*2)];
        for(counter = 0; counter < size; counter++) {
            creds[counter] = tmp[counter];
            slotStatus[counter] = tmpStatus[counter];
        }
        tmp = null;
        tmpStatus = null;
        // Delete objects we used to copy
        JCSystem.requestObjectDeletion();
        // Return the first free slot in the new array, which is going to be the counter plus 1
        return (short) (counter + (short) 1);
    }
    /**
     * Get the size of the array.
     * @return the array size
     */
    public short getLength() {
        return size;
    }
    /**
     * Returns the credential at position, or null if none.
     * @param position the position to get.
     * @return the credential, or null.
     */
    public StoredCredential getCred(short position) {
        return creds[position];
    }
}
