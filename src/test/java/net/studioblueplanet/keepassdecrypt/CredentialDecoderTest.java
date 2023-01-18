/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import java.util.List;
import net.studioblueplanet.keepassdecrypt.KeepassDatabase.PasswordCipher;
import net.studioblueplanet.keepassdecrypt.CredentialDecoder.Credential;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jorgen
 */
public class CredentialDecoderTest
{
    
    public CredentialDecoderTest()
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

    @Test
    public void testCredentialDecoder()
    {
        KeepassDatabase base            =new KeepassDatabase("src/test/resources/test3.kdbx");
        String          xml             =base.decryptDatabase("testtest");
        PasswordCipher  cipher          =base.getPasswordEncryption();
        byte[]          key             =base.getPasswordEncryptionKey();
        CredentialDecoder creds=new CredentialDecoder(xml, cipher, key);
        List<Credential>    credentials=creds.getCredentials();
        
        assertEquals(3, credentials.size());
        assertEquals("Sample Entry" , credentials.get(0).title);
        assertEquals("test"         , credentials.get(1).username);
        assertEquals("Password"     , credentials.get(0).password);
        assertEquals("test12345#"   , credentials.get(1).password);
        assertEquals("12345"        , credentials.get(2).password);
    }
    
}
