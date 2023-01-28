/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import net.studioblueplanet.keepassdecrypt.DatabaseHeader.PasswordCipher;

/**
 *
 * @author jorgen
 */
public class KeepassDatabaseTest
{
    
    public KeepassDatabaseTest()
    {
    }
    
    @BeforeClass
    public static void setUpClass()
    {
    }
    
    @AfterClass
    public static void tearDownClass()
    {
    }
    
    @Before
    public void setUp()
    {
    }
    
    @After
    public void tearDown()
    {
    }

    /**
     * Test of decryptDatabase method, of class KeepassDatabase.
     */
    @Test
    public void testDecryptDatabase3() throws IOException
    {
        System.out.println("decryptDatabase");
        String password = "";
        KeepassDatabase instance = new KeepassDatabase("src/test/resources/test.kdbx");
        String expResult = new String(Files.readAllBytes((new File("src/test/resources/test.kdbx.xml")).toPath()));
        String result = instance.decryptDatabase("test");
        assertEquals(expResult, result);
        result=instance.decryptDatabase("wrongpassword");
        assertEquals(null, result);
    }

    /**
     * Test of decryptDatabase method, of class KeepassDatabase.
     */
    @Test
    public void testDecryptDatabase3NoZip() throws IOException
    {
        System.out.println("decryptDatabase");
        String password = "";
        KeepassDatabase instance = new KeepassDatabase("src/test/resources/test_nozip.kdbx");
        String expResult = new String(Files.readAllBytes((new File("src/test/resources/test_nozip.kdbx.xml")).toPath()));
        String result = instance.decryptDatabase("test");
        assertEquals(expResult, result);
    }    

    /**
     * Test of decryptDatabase method, of class KeepassDatabase.
     */
    @Test
    //@Ignore
    public void testDecryptDatabase4ChaChaAesNozip() throws IOException
    {
        System.out.println("decryptDatabase");
        String password = "test";
        KeepassDatabase instance = new KeepassDatabase("src/test/resources/test_chacha_aes_nozip.kdbx");
        String expResult = new String(Files.readAllBytes((new File("src/test/resources/test_chacha_aes_nozip.kdbx.xml")).toPath()));
        String result = instance.decryptDatabase("test");
        assertEquals(expResult, result);
    }    

    /**
     * Test of decryptDatabase method, of class KeepassDatabase.
     */
    @Test
    //@Ignore
    public void testDecryptDatabase4ChaChaAes() throws IOException
    {
        System.out.println("decryptDatabase");
        String password = "test";
        KeepassDatabase instance = new KeepassDatabase("src/test/resources/test_chacha_aes.kdbx");
        String expResult = new String(Files.readAllBytes((new File("src/test/resources/test_chacha_aes.kdbx.xml")).toPath()));
        String result = instance.decryptDatabase("test");
        System.out.println(result);
        assertEquals(expResult, result);
    }    

    /**
     * Test of decryptDatabase method, of class KeepassDatabase.
     */
    @Test
    @Ignore
    public void testDecryptDatabase4ChaChaArgon2d() throws IOException
    {
        System.out.println("decryptDatabase");
        String password = "test";
        KeepassDatabase instance = new KeepassDatabase("src/test/resources/test_chacha_argon2d.kdbx");
        String expResult = new String(Files.readAllBytes((new File("src/test/resources/test_chacha_argon.kdbx.xml")).toPath()));
        String result = instance.decryptDatabase("test");
        System.out.println(result);
        assertEquals(expResult, result);
    }    
 
    /**
     * Test of testPassword method, of class KeepassDatabase.
     */
    @Test
    public void testTestPassword()
    {
        // KDBX 3
        System.out.println("testPassword");
        KeepassDatabase instance    = new KeepassDatabase("src/test/resources/test.kdbx");
        boolean expResult           = false;
        boolean result              = instance.testPassword("wrong password");
        assertEquals(expResult, result);
        expResult                   = true;
        result                      = instance.testPassword("test");
        assertEquals(expResult, result);

        // KDBX 4
        instance                    = new KeepassDatabase("src/test/resources/test_chacha_aes_nozip.kdbx");
        expResult                   = false;
        result                      = instance.testPassword("wrong password");
        assertEquals(expResult, result);
        expResult                   = true;
        result                      = instance.testPassword("test");
        assertEquals(expResult, result);

    }
    
    /**
     * Test of getPasswordEncryption method, of class KeepassDatabase.
     */
    @Test
    public void testgGetPasswordEncryption()
    {
        System.out.println("testPassword");
        String password = "";
        KeepassDatabase instance = new KeepassDatabase("src/test/resources/test.kdbx");
        PasswordCipher expResult=PasswordCipher.SALSA20;
        PasswordCipher result=instance.getPasswordEncryption();
        assertEquals(expResult, result);
    }
  
    /**
     * Test of getPasswordEncryptionKey method, of class KeepassDatabase.
     */
    @Test
    public void testgGetPasswordEncryptionKey()
    {
        System.out.println("testPassword");
        String password = "";
        KeepassDatabase instance = new KeepassDatabase("src/test/resources/test.kdbx");
        byte[] expResult={(byte)0x6b, (byte)0x25, (byte)0xc9, (byte)0xd7, (byte)0x0e, (byte)0x5c, (byte)0x19, (byte)0xac, 
                          (byte)0x51, (byte)0x74, (byte)0xd7, (byte)0x74, (byte)0x53, (byte)0xad, (byte)0x23, (byte)0x70, 
                          (byte)0x15, (byte)0x27, (byte)0x56, (byte)0x2e, (byte)0x02, (byte)0xb8, (byte)0xec, (byte)0x5c, 
                          (byte)0xac, (byte)0x89, (byte)0x2d, (byte)0xc3, (byte)0xe4, (byte)0xb5, (byte)0x1c, (byte)0x12};
        byte[] result   =instance.getPasswordEncryptionKey();
        assertArrayEquals(expResult, result);
    }

    
}
