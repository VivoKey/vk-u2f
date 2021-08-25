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

import javacard.framework.Util;

public class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
    public byte[] id;
    public DomString displayName;
    // 3-bit. 0 is the parent name, 1 is the id, 2 is the displayName.
    public boolean[] dataPresent;
    public byte numData;

    public byte[] icon;

    public PublicKeyCredentialUserEntity() {
        dataPresent = new boolean[4];
        numData = 0;
    }

    public void setId(byte[] src, short off, short len) {
        id = new byte[len];
        Util.arrayCopy(src, off, id, (short) 0, len);
        if (!dataPresent[1]) {
            dataPresent[1] = true;
            numData++;
        }
    }

    public void setIcon(byte[] src, short off, short len) {
        icon = new byte[len];
        Util.arrayCopy(src, off, id, (short) 0, len);
        if (!dataPresent[3]) {
            dataPresent[3] = true;
            numData++;
        }
    }

    public void setDisplayName(byte[] src, short len) {
        displayName = new DomString(src, len);
        if (!dataPresent[2]) {
            dataPresent[2] = true;
            numData++;
        }
    }

    /**
     * Checks the id against the src byte array.
     * 
     * @param src source byte array
     * @param off offset in the byte array to start at
     * @param len length of the id in the source byte array
     * @return if they match
     */
    public boolean checkId(byte[] src, short off, short len) {
        if (len != (short) id.length) {
            return false;
        }
        return (Util.arrayCompare(src, off, id, (short) 0, len) == 0);
    }

    public void setName(byte[] pkName, short len) {
        name = new DomString(pkName, len);
        if (!dataPresent[0]) {
            dataPresent[0] = true;
            numData++;
        }
    }

    /**
     * Convenience method to check two PublicKeyCredentialUserEntity objects
     * 
     * @param other the second PublicKeyCredentialUserEntity to compare
     * @return if they match
     */
    public boolean checkId(PublicKeyCredentialUserEntity other) {
        return other.checkId(id, (short) 0, ((short) id.length));
    }

}
