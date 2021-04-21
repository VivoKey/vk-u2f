/*
**
** Copyright 2019, The Android Open Source Project
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

public class ICUtil {

    /**
     * Get the sign bit of a given short (returns 0 or 1)
     */
    public static short sign(short a) {
        return (byte) ((a >>> (short) 15) & 1);
    }

    /**
     * Return the smaller short of two given values
     */
    public static short min(short a, short b) {
        if (a < b) {
            return a;
        }
        return b;
    }

    /**
     * Return the bigger short of two given values
     */
    public static short max(short a, short b) {
        if (a > b) {
            return a;
        }
        return b;
    }

    /**
     * Set the bit in a given bitfield array
     * 
     * @param bitField The bitfield array
     * @param flag     Index in the bitfield where the bit should be set
     * @param value    Sets bit to 0 or 1
     */
    public static void setBit(byte[] bitField, short flag, boolean value) {
        short byteIndex = (short) (flag >>> (short) 3);
        byte bitMask = (byte) ((byte) 1 << (short) (flag & (short) 0x0007));
        if (value) {
            bitField[byteIndex] |= bitMask;
        } else {
            bitField[byteIndex] &= ~bitMask;
        }
    }

    /**
     * Get the value of a bit inside a bitfield
     * 
     * @param bitField The bitfield 
     * @param flag     Index in the bitfield that should be read
     * @return Value at the index (0 or 1)
     */
    public static boolean getBit(byte bitField, byte flag) {
        byte bitMask = (byte) ((byte) 1 << (short) (flag & 0x07));
        return bitMask == (byte) (bitField & bitMask);
    }

    /**
     * Set the bit in a given bitfield 
     * 
     * @param bitField The bitfield 
     * @param flag     Index in the bitfield where the bit should be set
     * @param value    Sets bit to 0 or 1
     */
    public static byte setBit(byte bitField, byte flag, boolean value) {
        byte bitMask = (byte) ((byte) 1 << (short) (flag & 0x07));
        if (value) {
            bitField |= bitMask;
        } else {
            bitField &= ~bitMask;
        }
        return bitField;
    }

    /**
     * Get the value of a bit inside a bitfield
     * 
     * @param bitField The bitfield array
     * @param flag     Index in the bitfield that should be read
     * @return Value at the index (0 or 1)
     */
    public static boolean getBit(byte[] bitField, short flag) {
        short byteIndex = (short) (flag >>> (short) 3);
        byte bitMask = (byte) ((byte) 1 << (short) (flag & (short) 0x0007));
        return bitMask == (byte) (bitField[byteIndex] & bitMask);
    }

    /**
     * Compare two signed shorts as unsigned value. Returns true if n1 is truly
     * smaller, false otherwise.
     */
    public static boolean isLessThanAsUnsignedShort(short n1, short n2) {
        return (n1 < n2) ^ ((n1 < 0) != (n2 < 0));
    }
    
    /**
     * Fill a provided short array with a given value.
     */
    public static short shortArrayFillNonAtomic(short[] buffer, short offset, short len, short value) {
        len += offset;
        for (; offset < len; offset++) {
            buffer[offset] = value;
        }
        return offset;
    }
}
