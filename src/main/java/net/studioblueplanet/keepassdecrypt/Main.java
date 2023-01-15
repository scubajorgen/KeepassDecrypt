/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author jorgen
 */
public class Main
{
    private final static Logger LOGGER = LogManager.getLogger(Main.class);
    public static void main(String[] args)
    {
        LOGGER.info("Starting database decryption");
        KeepassDatabase base=new KeepassDatabase("test_5charspassword.kdbx");
        String xml=base.decryptDatabase("test");
        base.dumpData();
        LOGGER.info("Decryption result:\n{}", xml);
        
        BruteForceTest test=new BruteForceTest("test_3charspassword.kdbx");
        long start = System.currentTimeMillis();
        test.execute(5);
        long end = System.currentTimeMillis();
        long elapsedTime = (end - start)/1000;
        LOGGER.info("It took {} seconds", elapsedTime);
        
    }
}
