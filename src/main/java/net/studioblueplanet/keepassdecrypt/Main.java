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
     * Show usage
     */
    private static void showHelp()
    {
        LOGGER.info("USAGE: ");
        LOGGER.info("Demo KDBX3.1 decryption                      : java -jar  KeypassDecrypt.jar test1");
        LOGGER.info("Demo KDBX4 ChaCha20 + KDF AES/EBC  decryption: java -jar  KeypassDecrypt.jar test2");
        LOGGER.info("Demo KDBX4 ChaCha20 + KDF ARGON2ID decryption: java -jar  KeypassDecrypt.jar test3");
        LOGGER.info("Demo brute force                             : java -jar  KeypassDecrypt.jar test4");
        LOGGER.info("Decrypt own file                             : java -jar  KeypassDecrypt.jar [filename.kdbx]\n\n");        
    }
    
    /**
     * Main function
     * @param args Not used
     */
    public static void main(String[] args)
    {
        if (args.length==1)
        {
            String command=args[0];
            if (command.toLowerCase().equals("test1"))
            {
                demoDecryption("test_8charspassword.kdbx"   , "testtest", "DECRYPT KDBX 3.1");
            }
            else if (command.toLowerCase().equals("test2"))
            {
                demoDecryption("test_chacha.kdbx"           , "test"    , "DECRYPT KDBX 4.0 - main: Chacha20 key generation: AES EBC");
            }
            else if (command.toLowerCase().equals("test3"))
            {
                demoDecryption("test_chacha_argon2id.kdbx"  , "test"    , "DECRYPT KDBX 4.0 - main: Chacha20 key generation: ARGON2ID");
            }
            else if (command.toLowerCase().equals("test4"))
            {
                demoBruteForce();
            }
            else
            {
                showHelp();
            }
        }
        else if (args.length==2)
        {
            String file     =args[0];
            String password =args[1];
            demoDecryption(file, password, "Decrypt own file");
        }
        else
        {
            showHelp();
            LOGGER.info("Running demo:");
            demoDecryption("test_chacha_argon2id.kdbx"  , "test"    , "DECRYPT KDBX 4.0 - main: Chacha20 key generation: ARGON2ID");
        }
    }
}
