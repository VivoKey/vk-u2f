package com.vivokey.u2f;

import javacard.framework.CardException;



/**
 * CTAP2 error, a "better" way for us to throw errors and propagate their reasons, to be processed upstream (in the CTAP2 module).
 * If this Exception is thrown, it's expected that the upstream command processing will convert it into a CTAP2 error (which is ISOException 9000, with additional status).
 */
public class CTAP2Exception extends CardException {

    // initialized when created by Dispatcher
    private static CTAP2Exception systemInstance;



    /**
     * Constructs a <code>CTAP2Exception</code> with the specified reason. To
     * conserve on resources use <code>throwIt()</code> to use the Java Card
     * runtime environment-owned instance of this class.
     * 
     * @param reason
     *            the reason for the exception
     */
    public CTAP2Exception(short reason) {
        super(reason);
        if (systemInstance == null) {
            systemInstance = this;
        }
    }
    
    
    /**
     * Throws the Java Card runtime environment-owned instance of
     * <code>CTAP2Exception</code> with the specified reason.
     * <p>
     * Java Card runtime environment-owned instances of exception classes are
     * temporary Java Card runtime environment Entry Point Objects and can be
     * accessed from any applet context. References to these temporary objects
     * cannot be stored in class variables or instance variables or array
     * components. See
     * <em>Runtime Environment Specification, Java Card Platform, Classic Edition</em>,
     * section 6.2.1 for details.
     * 
     * @param reason
     *            the reason for the exception
     * @exception CTAP2Exception
     *                always
     */
    public static void throwIt(short reason) throws CTAP2Exception {
        systemInstance.setReason(reason);
        throw systemInstance;
    }


    /**
     * Throws the Java Card runtime environment-owned instance of
     * <code>CTAP2Exception</code> with the specified reason.
     * <p>
     * Java Card runtime environment-owned instances of exception classes are
     * temporary Java Card runtime environment Entry Point Objects and can be
     * accessed from any applet context. References to these temporary objects
     * cannot be stored in class variables or instance variables or array
     * components. See
     * <em>Runtime Environment Specification, Java Card Platform, Classic Edition</em>,
     * section 6.2.1 for details.
     * 
     * @param reason
     *            the reason for the exception
     * @exception CTAP2Exception
     *                always
     */
    public static void throwIt(byte reason) throws CTAP2Exception {
        systemInstance.setReason(reason);
        throw systemInstance;
    }
}
