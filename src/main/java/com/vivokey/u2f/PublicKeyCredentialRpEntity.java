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

public class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
    DomString rpId;
    
    public void setRp(byte[] pkId, short len) {
        rpId = new DomString(pkId, len);
    }
    /**
     * Checks the RP ID against the internal DomString.
     * @param inBuf
     * @param inOff
     * @param inLen
     * @return
     */
    public boolean checkId(byte[] inBuf, short inOff, short inLen) {
        return rpId.checkEquals(inBuf, inOff, inLen);
    }
    /**
     * Convenience method to simplify checking two PublicKeyCredentialRpEntity objects.
     * @param other the other object to check
     * @return if they match
     */
    public boolean checkId(PublicKeyCredentialRpEntity other) {
        return rpId.checkEquals(other.rpId);
    }

    public void getRp(byte[] buf, short off) {
        Util.arrayCopy(rpId.str, rpId.len, buf, off, rpId.len);
    }
    public short getRpLen() {
        return rpId.len;
    }

}
