/*
**
** Copyright 2018, The Android Open Source Project
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

package android.security.identity_credential;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public abstract class CBORBase {

    // Mask for the major CBOR type
    protected static final byte MAJOR_TYPE_MASK = (byte) 0x07;

    // Mask for additional information in the low-order 5 bits 
    protected static final byte ADDINFO_MASK = (byte) 0x1F;
    
    // Major type 0: an unsigned integer
    public static final byte TYPE_UNSIGNED_INTEGER = (byte) (0x00);
    // Major type 1: a negative integer
    public static final byte TYPE_NEGATIVE_INTEGER = (byte) (0x01);
    // Major type 2: a byte string
    public static final byte TYPE_BYTE_STRING = (byte) (0x02);
    // Major type 3: a text string
    public static final byte TYPE_TEXT_STRING = (byte) (0x03);
    // Major type 4: an array of data items
    public static final byte TYPE_ARRAY = (byte) (0x04);
    // Major type 5: a map of pairs of data items
    public static final byte TYPE_MAP = (byte) (0x05);
    // Major type 6: optional semantic tagging of other major types
    public static final byte TYPE_TAG = (byte) (0x06);
    // Major type 7: floating-point numbers
    public static final byte TYPE_FLOAT = (byte) (0x07);
    
    /** 
     * Length information (Integer size, array length, etc.) in low-order 5 bits
     */
    // One byte unsigned value (uint8)
    protected static final byte ENCODED_ONE_BYTE = 0x18;
    // Two byte unsigned value (uint16)
    protected static final byte ENCODED_TWO_BYTES = 0x19;
    // Four byte unsigned value (uint32)
    protected static final byte ENCODED_FOUR_BYTES = 0x1a;
    // Eight byte unsigned value (uint64)
    protected static final byte ENCODED_EIGHT_BYTES = 0x1b;

    /** 
     * Values for additional information in major type 7
     */
    // CBOR encoded boolean - false
    protected static final byte ENCODED_FALSE = (byte) 0xF4;
    // CBOR encoded boolean - true
    protected static final byte ENCODED_TRUE = (byte) 0xF5;
    // CBOR encoded null
    protected static final byte ENCODED_NULL = (byte) 0xF6;
    // CBOR encoded undefined value
    protected static final byte ENCODED_UNDEFINED = (byte) 0xF7;
    
    // CBOR encoded break for unlimited arrays/maps.
    protected static final byte ENCODED_BREAK = (byte) 0xFF;

    public static final byte INVALID_INPUT = -1;

    protected short[] mStatusWords;
    
    protected byte[] mBuffer;
    
    protected CBORBase() {
        mStatusWords = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);     
    }

    /**
     * Initializes the encoder/decoder without buffer (use the APDU buffer instead).
     * 
     * @param offset Offset in APDU buffer where content should be read
     * @param length Length in the APDU buffer
     */
    final public void init(short off, short length) {
        mBuffer = null;
        mStatusWords[0] = off;
        mStatusWords[1] = (short)(off + length);
    }
    /**
     * Initializes with a given array and the given offset.
     * @param buffer Buffer with CBOR content
     * @param offset Offset in buffer where content should be read/written
     */
    final public void init(byte[] buffer, short off, short length) {
        if (buffer != APDU.getCurrentAPDUBuffer()) { // do not store the APDU buffer
            mBuffer = buffer;
        } else {
            mBuffer = null;
        }
        mStatusWords[0] = off;
        mStatusWords[1] = (short)(off + length);
    }
    /**
     * Reset the internal state of the parser 
     */
    final public void reset() {
        mBuffer = null;
        mStatusWords[0] = 0;
        mStatusWords[1] = 0;
    }

    /**
     * Returns the current offset within the buffer stream.
     */
    final public short getCurrentOffset() {
        return mStatusWords[0];
    }

    /**
     * Returns the length of the current buffer stream.
     */
    final public short getBufferLength() {
        return mStatusWords[1];
    }
    
    /**
     * Returns the current offset in the buffer stream and increases it by the given
     * number
     * 
     * @param inc Value that should be add to the offset
     * @return Current offset value (before increase)
     */
    final protected short getCurrentOffsetAndIncrease(short inc) {
        final short off = mStatusWords[0];
        increaseOffset(inc);
        return off;
    }

    /**
     * Get the current raw byte (do not increase offset
     * @return Current byte value
     */
    protected byte getRawByte() {
        return getBuffer()[mStatusWords[0]];
    }

    /**
     * Returns the internal buffer or the APDU buffer if non is initializes
     * 
     * @return The buffer for encoding/decoding
     */
    protected byte[] getBuffer() {
        if(mBuffer == null) {
            return APDU.getCurrentAPDUBuffer();
        } 
        return mBuffer;
    }
    
    /**
     * Increase the current offset and return the new value.
     * 
     * @param inc Value that should be added to the offset
     * @return New offset value (after increase)
     */
    final protected short increaseOffset(short inc) {
        if((short)(getCurrentOffset() + inc) > getBufferLength() || inc < 0)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        mStatusWords[0]+=inc;
        return mStatusWords[0];
    }
}
