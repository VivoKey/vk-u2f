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

import javacard.security.ECKey;

public class KeyParams {
	// Prime spec for the field
	public final static byte[] secp256r1p = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
	// A
	public final static byte[] secp256r1A = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC};
	// B
	public final static byte[] secp256r1B = new byte[] {(byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, 
			(byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, 
			(byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B};
	// G
	public final static byte[] secp256r1G = new byte[] {(byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, 
			(byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0, (byte) 0xF4, (byte) 0xA1,
			(byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B, (byte) 0x8E,
			(byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE, 
			(byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5};
	// Order of G
	public final static byte[] secp256r1R = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, 
			(byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51};
	// Cofactor of G
	public final static short secp256r1K = 1;
	
	
	public static void sec256r1params(ECKey setKey) {
		// Set the key parameters from above
		
		// Set field
		setKey.setFieldFP(KeyParams.secp256r1p, (short)0, (short) 32);
		setKey.setA(KeyParams.secp256r1A, (short)0, (short) 32);
		setKey.setB(KeyParams.secp256r1B, (short)0, (short) 32);
		setKey.setG(KeyParams.secp256r1G, (short)0, (short) 65);
		setKey.setR(KeyParams.secp256r1R, (short)0, (short) 32);
		setKey.setK(KeyParams.secp256r1K);
		}
	
}
