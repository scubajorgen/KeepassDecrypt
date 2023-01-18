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
        System.out.println("execute");
        int maxChars = 1;
        
        // password found
        BruteForceTest instance = new BruteForceTest("src/test/resources/test2.kdbx");
        boolean expResult = true;
        boolean result = instance.execute(1);
        assertEquals(expResult, result);
        
        // password not found
        instance = new BruteForceTest("src/test/resources/test.kdbx");
        expResult = false;
        result = instance.execute(2);
        assertEquals(expResult, result);
    }
    
}
