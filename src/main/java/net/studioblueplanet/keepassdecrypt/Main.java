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
    
    
    /**
     * Demo of decryption
     * @param file File name of kdbx file
     * @param password Password of kdbx file
     * @param title Some title to display
     */
    public static void demoDecryption(String file, String password, String title)
    {
        LOGGER.info("#################################################################################");
        LOGGER.info("# {}", title);
        LOGGER.info("#################################################################################");
        KeepassDatabase base    =new KeepassDatabase(file);
        String xml              =base.decryptDatabase(password);
        base.dumpData();
        LOGGER.info("Decryption result:\n{}", xml);        
        // CREDENTIAL PASSWORD DECRYPTION
        CredentialDecoder decoder=new CredentialDecoder(xml, base.getPasswordEncryption(), base.getPasswordEncryptionKey());
        
        for(Credential c : decoder.getCredentials())
        {
            LOGGER.info("Credential for entry '{}': username '{}' password '{}'", c.title, c.username, c.password);
        }
    }
    
    /**
     * Brute force password testing
     */
    public static void demoBruteForce()
    {
        LOGGER.info("#################################################################################");
        LOGGER.info("# BRUTE FORCE TEST");
        LOGGER.info("#################################################################################");
        BruteForceTest test=new BruteForceTest("test_3charspassword.kdbx");
        long start = System.currentTimeMillis();
        test.execute(5);
        long end = System.currentTimeMillis();
        long elapsedTime = (end - start)/1000;
        LOGGER.info("It took {} seconds", elapsedTime);        
    }

    /**
     * Main function
     * @param args Not used
     */
    public static void main(String[] args)
    {
        // DATABASE DECRYPTION
        demoDecryption("test_8charspassword.kdbx"   , "testtest", "DECRYPT KDBX 3.1");
        demoDecryption("test_chacha.kdbx"           , "test"    , "DECRYPT KDBX 4.0 - main: Chacha20 key generation: AES EBC");
        demoDecryption("test_chacha_argon2id.kdbx"  , "test"    , "DECRYPT KDBX 4.0 - main: Chacha20 key generation: ARGON2ID");
        demoBruteForce();
    }
}
