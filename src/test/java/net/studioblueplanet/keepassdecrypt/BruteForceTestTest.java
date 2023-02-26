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

/**
 *
 * @author jorgen
 */
public class BruteForceTestTest
{
    
    public BruteForceTestTest()
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
     * Test of execute method, of class BruteForceTest.
     */
    @Test
    public void testExecute()
    {
        System.out.println("execute kdbx3");
        int maxChars = 1;
        
        // KDBX 3
        // password found
        BruteForceTest instance = new BruteForceTest("src/test/resources/test2.kdbx");
        boolean expResult = true;
        boolean result = instance.execute(1);
        assertEquals(expResult, result);
        
        // password found
        instance = new BruteForceTest("src/test/resources/test.kdbx");
        instance.setPasswordChars("taes");
        expResult = true;
        result = instance.execute(4);
        assertEquals(expResult, result);
        
        // password not found
        instance = new BruteForceTest("src/test/resources/test.kdbx");
        instance.setPasswordChars("abestX");
        expResult = false;
        result = instance.execute(2);
        assertEquals(expResult, result);
    }    /**
     * Test of execute method, of class BruteForceTest.
     */
    @Test
    public void testExecuteKdbx4()
    {
        System.out.println("execute kdbx4");
        int maxChars = 1;
        
        // KDBX 4
        // password found
        BruteForceTest instance = new BruteForceTest("src/test/resources/test_chacha_aes_nozip2.kdbx");
        boolean expResult = true;
        boolean result = instance.execute(1);
        assertEquals(expResult, result);
        
        // password not found
        instance = new BruteForceTest("src/test/resources/test.kdbx");
        instance.setPasswordChars("abestX");
        expResult = false;
        result = instance.execute(2);
        assertEquals(expResult, result);
    }
 
    
}
