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
package com.vivokey.u2f.CTAPObjects;

import javacard.framework.Util;

public class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
    byte[] id;
    DomString displayName;
    
    public void setId(byte[] src, short off, short len) {
        id = new byte[len];
        Util.arrayCopy(src, off, id, (short) 0, len);
    }
    public void setDisplayName(byte[] src, short len) {
        displayName = new DomString(src, len);
    }
    /**
     * Checks the id against the src byte array.
     * @param src source byte array
     * @param off offset in the byte array to start at
     * @param len length of the id in the source byte array
     * @return if they match
     */
    public boolean checkId(byte[] src, short off, short len) {
        if(len != (short) id.length) {
            return false;
        }
        return (Util.arrayCompare(src, off, id, (short) 0, len) == 0);
    }

    /**
     * Convenience method to check two PublicKeyCredentialUserEntity objects
     * @param other the second PublicKeyCredentialUserEntity to compare
     * @return if they match
     */
    public boolean checkId(PublicKeyCredentialUserEntity other) {
        return other.checkId(id, (short) 0, ((short) id.length));
    }

}
