package com.vivokey.u2f;

import javacard.framework.CardRuntimeException;

public class CTAP2Exception extends CardRuntimeException {

    public CTAP2Exception(short reason) {
        super(reason);
    }

    
}
