package com.vivokey.u2f;

import static org.junit.Assert.assertTrue;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import org.junit.Test;

import javacard.framework.AID;

/**
 * Unit testing via jCardSim
 */
public class AppTest 
{
    /**
     * Check if applet installs.
     */
    @Test
    public void shouldInstallSelect()
    {
        CardSimulator sim = new CardSimulator();
        AID appletAID = AIDUtil.create("A0000006472F0001");
        sim.installApplet(appletAID, CTAP2.class);
        assertTrue(sim.selectApplet(appletAID));
    }
}
