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
    byte[] type;
    byte[] id;
    public PublicKeyCredentialDescriptor(byte[] pkId, short offset, short len) {
        type = new byte[(short) (Utf8Strings.UTF8_PUBLIC_KEY.length)];
        Util.arrayCopy(Utf8Strings.UTF8_PUBLIC_KEY, (short) 0, type, (short) 0, (short) type.length);
        id = new byte[len];
        Util.arrayCopy(pkId, offset, id, (short) 0, (short) id.length);
    }
}
