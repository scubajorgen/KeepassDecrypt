/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import net.studioblueplanet.keepassdecrypt.CredentialDecoder.Credential;
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
        // DATABASE DECRYPTION
        LOGGER.info("Starting database decryption");
        KeepassDatabase base=new KeepassDatabase("test_8charspassword.kdbx");
        String xml=base.decryptDatabase("testtest");
        base.dumpData();
        LOGGER.info("Decryption result:\n{}", xml);
        
        // CREDENTIAL PASSWORD DECRYPTION
        CredentialDecoder decoder=new CredentialDecoder(xml, base.getPasswordEncryption(), base.getPasswordEncryptionKey());
        
        for(Credential c : decoder.getCredentials())
        {
            LOGGER.info("Credential for entry '{}': username '{}' password '{}'", c.title, c.username, c.password);
        }
       
        // BRUTE FORCE TEST
        BruteForceTest test=new BruteForceTest("test_3charspassword.kdbx");
        long start = System.currentTimeMillis();
        test.execute(5);
        long end = System.currentTimeMillis();
        long elapsedTime = (end - start)/1000;
        LOGGER.info("It took {} seconds", elapsedTime);
        
    }
}
