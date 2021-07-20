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

public class PublicKeyCredentialDescriptor {
    private byte[] id;
    private static final byte[] type = {'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'};
    public PublicKeyCredentialDescriptor(byte[] id, short off, short len) {
        this.id = new byte[len];
        Util.arrayCopy(id, off, this.id, (short) 0, len);
        // TODO: Finish
    }

}
