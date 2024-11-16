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

import com.password4j.Argon2Function;
import com.password4j.types.Argon2;
/**
 *
 * @author jorgen
 */
public class Argon2FunctionTest
{
    
    public Argon2FunctionTest()
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
     * Test of getInstance method, of class Argon2Function.
     */
    @Test
    public void testHash()
    {
        System.out.println("hash");
        int memory = 256;
        int iterations = 3;
        int parallelism = 2;
        int outputLength = 32;
        byte[] salt="3DdBWxD2EYVpeidv".getBytes();
        byte[] password="Test".getBytes();
        Argon2 type = Argon2.D;
        Argon2Function instance=Argon2Function.getInstance(memory, iterations, parallelism, outputLength, type);
        byte[] hash=instance.hash(password, salt).getBytes();
        String expResult = "77c24e0652181669c6d5c7d15fc802917eba14a98a36abe9c171ec77ed997a3b";
        assertEquals(expResult, Toolbox.bytesToString(hash));
    }
   
    /**
     * Test of getInstance method, of class Argon2Function.
     */
    @Test
    public void testHashTimed()
    {
        System.out.println("hash timed");
        int memory          = 65536;
        int iterations      = 2;
        int parallelism     = 3;
        int outputLength    = 32;
        int version         = 0x13;
        byte[] salt         =
        {
            (byte) 0x6b, (byte) 0x25, (byte) 0xc9, (byte) 0xd7, (byte) 0x0e, (byte) 0x5c, (byte) 0x19, (byte) 0xac,
            (byte) 0x51, (byte) 0x74, (byte) 0xd7, (byte) 0x74, (byte) 0x53, (byte) 0xad, (byte) 0x23, (byte) 0x70,
            (byte) 0x15, (byte) 0x27, (byte) 0x56, (byte) 0x2e, (byte) 0x02, (byte) 0xb8, (byte) 0xec, (byte) 0x5c,
            (byte) 0xac, (byte) 0x89, (byte) 0x2d, (byte) 0xc3, (byte) 0xe4, (byte) 0xb5, (byte) 0x1c, (byte) 0x12
        };
        byte[] password="Test".getBytes();
        Argon2 type = Argon2.ID;
        Argon2Function instance=Argon2Function.getInstance(memory, iterations, parallelism, outputLength, type, version);
        long start = System.currentTimeMillis();
        byte[] hash=instance.hash(password, salt).getBytes();
        long end = System.currentTimeMillis();
        System.out.println("Argon2id hash took "+(end-start)+" ms");
        String expResult = "cbcfdee482c233e525ca405c7014e89cd33142758a2f1d23c420690f950c988c";
        assertEquals(expResult, Toolbox.bytesToString(hash));
    }
   
}
