package com.vivokey.u2f;

import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

/**
 * Attestation keypair object. 
 */
public class AttestationKeyPair {
    private KeyPair kp;
    private Signature sig;
    public byte[] x509cert;
    public AttestationKeyPair() {
        kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        // Generate a new keypair for attestation.
        kp.genKeyPair();
        // Initialise a signature object
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sig.init(kp.getPrivate(), Signature.MODE_SIGN);
    }
    /**
     * Signs a byte array with the attestation keypair.
     * @param inBuf Buffer to sign from.
     * @param inOff Offset to begin at.
     * @param inLen Length of data to sign.
     * @param sigBuf Buffer to sign into.
     * @param sigOff Offset to begin at.
     */
    public short sign(byte[] inBuf, short inOff, short inLen, byte[] sigBuf, short sigOff) {
        return sig.sign(inBuf, inOff, inLen, sigBuf, sigOff);
    }
    /**
     * Sets the attestation certificate. 
     * @param inBuf buffer to read from
     * @param inOff offset to begin reading from
     * @param inLen length of certificate.
     */
    public void setCert(byte[] inBuf, short inOff, short inLen) {
        x509cert = new byte[inLen];
        Util.arrayCopy(inBuf, inOff, x509cert, (short) 0, inLen);
    }

    /**
     * Gets the attestation certificate. 
     * @param outBuf the buffer to read into.
     * @param outOff the offset to begin at.
     * @return the length of the certificate.
     */
    public short getCert(byte[] outBuf, short outOff) {
        Util.arrayCopy(x509cert, (short) 0, outBuf, outOff,(short) x509cert.length);
        return (short) x509cert.length;
    }
}
