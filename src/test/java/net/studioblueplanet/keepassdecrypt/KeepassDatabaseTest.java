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
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

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
    public void testDecryptDatabase() throws IOException
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
     * Test of testPassword method, of class KeepassDatabase.
     */
    @Test
    public void testTestPassword()
    {
        System.out.println("testPassword");
        String password = "";
        KeepassDatabase instance = new KeepassDatabase("src/test/resources/test.kdbx");;
        boolean expResult = false;
        boolean result = instance.testPassword("wrong password");
        assertEquals(expResult, result);
        expResult = true;
        result = instance.testPassword("test");
        assertEquals(expResult, result);

    }


    
}
