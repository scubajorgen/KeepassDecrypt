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
public class ToolboxTest
{
    
    public ToolboxTest()
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
     * Test of hmacSha256 method, of class Toolbox.
     */
    @Test
    public void testHmacSha256()
    {
        System.out.println("hmacSha256");
        byte[] data = {'t', 'e', 's', 't'};
        byte[] key = {'k', 'e', 'y'};
        byte[] expResult = {(byte)0x02, (byte)0xaf, (byte)0xb5, (byte)0x63, (byte)0x04, (byte)0x90, (byte)0x2c, (byte)0x65,
                            (byte)0x6f, (byte)0xcb, (byte)0x73, (byte)0x7c, (byte)0xdd, (byte)0x03, (byte)0xde, (byte)0x62, 
                            (byte)0x05, (byte)0xbb, (byte)0x6d, (byte)0x40, (byte)0x1d, (byte)0xa2, (byte)0x81, (byte)0x2e, 
                            (byte)0xfd, (byte)0x9b, (byte)0x2d, (byte)0x36, (byte)0xa0, (byte)0x8a, (byte)0xf1, (byte)0x59};
        byte[] result = Toolbox.hmacSha256(data, key);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of sha256 method, of class Toolbox.
     */
    @Test
    public void testSha256()
    {
        System.out.println("sha256");
        byte[] data = {'t', 'e', 's', 't'};
        byte[] expResult = {(byte)0x9f, (byte)0x86, (byte)0xd0, (byte)0x81, (byte)0x88, (byte)0x4c, (byte)0x7d, (byte)0x65, 
                            (byte)0x9a, (byte)0x2f, (byte)0xea, (byte)0xa0, (byte)0xc5, (byte)0x5a, (byte)0xd0, (byte)0x15, 
                            (byte)0xa3, (byte)0xbf, (byte)0x4f, (byte)0x1b, (byte)0x2b, (byte)0x0b, (byte)0x82, (byte)0x2c, 
                            (byte)0xd1, (byte)0x5d, (byte)0x6c, (byte)0x15, (byte)0xb0, (byte)0xf0, (byte)0x0a, (byte)0x08};
        byte[] result = Toolbox.sha256(data);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of sha512 method, of class Toolbox.
     */
    @Test
    public void testSha512()
    {
        System.out.println("sha512");
        byte[] data = {'t', 'e', 's', 't'};
        byte[] expResult = {(byte)0xee, (byte)0x26, (byte)0xb0, (byte)0xdd, (byte)0x4a, (byte)0xf7, (byte)0xe7, (byte)0x49, 
                            (byte)0xaa, (byte)0x1a, (byte)0x8e, (byte)0xe3, (byte)0xc1, (byte)0x0a, (byte)0xe9, (byte)0x92, 
                            (byte)0x3f, (byte)0x61, (byte)0x89, (byte)0x80, (byte)0x77, (byte)0x2e, (byte)0x47, (byte)0x3f, 
                            (byte)0x88, (byte)0x19, (byte)0xa5, (byte)0xd4, (byte)0x94, (byte)0x0e, (byte)0x0d, (byte)0xb2, 
                            (byte)0x7a, (byte)0xc1, (byte)0x85, (byte)0xf8, (byte)0xa0, (byte)0xe1, (byte)0xd5, (byte)0xf8, 
                            (byte)0x4f, (byte)0x88, (byte)0xbc, (byte)0x88, (byte)0x7f, (byte)0xd6, (byte)0x7b, (byte)0x14, 
                            (byte)0x37, (byte)0x32, (byte)0xc3, (byte)0x04, (byte)0xcc, (byte)0x5f, (byte)0xa9, (byte)0xad, 
                            (byte)0x8e, (byte)0x6f, (byte)0x57, (byte)0xf5, (byte)0x00, (byte)0x28, (byte)0xa8, (byte)0xff};
        byte[] result = Toolbox.sha512(data);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of validateSha256Hash method, of class Toolbox.
     */
    @Test
    public void testValidateSha256Hash()
    {
        System.out.println("validateSha256Hash");
        byte[] data = {'t', 'e', 's', 't'};
        byte[] hash = {(byte)0x9f, (byte)0x86, (byte)0xd0, (byte)0x81, (byte)0x88, (byte)0x4c, (byte)0x7d, (byte)0x65, 
                       (byte)0x9a, (byte)0x2f, (byte)0xea, (byte)0xa0, (byte)0xc5, (byte)0x5a, (byte)0xd0, (byte)0x15, 
                       (byte)0xa3, (byte)0xbf, (byte)0x4f, (byte)0x1b, (byte)0x2b, (byte)0x0b, (byte)0x82, (byte)0x2c, 
                       (byte)0xd1, (byte)0x5d, (byte)0x6c, (byte)0x15, (byte)0xb0, (byte)0xf0, (byte)0x0a, (byte)0x08};
        boolean result = Toolbox.validateSha256Hash(data, hash);
        assertEquals(true, result);
        hash[0]=(byte)0x9e;
        result = Toolbox.validateSha256Hash(data, hash);
        assertEquals(false, result);
    }

    /**
     * Test of validateHmacSha256Hash method, of class Toolbox.
     */
    @Test
    public void testValidateHmacSha256Hash()
    {
        System.out.println("validateHmacSha256Hash");
        byte[] data = {'t', 'e', 's', 't'};
        byte[] key = {'k', 'e', 'y'};
        byte[] hash = {(byte)0x02, (byte)0xaf, (byte)0xb5, (byte)0x63, (byte)0x04, (byte)0x90, (byte)0x2c, (byte)0x65,
                       (byte)0x6f, (byte)0xcb, (byte)0x73, (byte)0x7c, (byte)0xdd, (byte)0x03, (byte)0xde, (byte)0x62, 
                       (byte)0x05, (byte)0xbb, (byte)0x6d, (byte)0x40, (byte)0x1d, (byte)0xa2, (byte)0x81, (byte)0x2e, 
                       (byte)0xfd, (byte)0x9b, (byte)0x2d, (byte)0x36, (byte)0xa0, (byte)0x8a, (byte)0xf1, (byte)0x59};
        boolean result = Toolbox.validateHmacSha256Hash(data, key, hash);
        assertEquals(true, result);
        hash[2]=(byte)0xb4;
        result = Toolbox.validateHmacSha256Hash(data, key, hash);
        assertEquals(false, result);
    }

    /**
     * Test of readInt method, of class Toolbox.
     */
    @Test
    public void testReadInt()
    {
        System.out.println("readInt");
        byte[] source = {0x78, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, (byte)0x87};
        long result = Toolbox.readInt(source, 0, 2);
        assertEquals(0x5678, result);
        result = Toolbox.readInt(source, 0, 4);
        assertEquals(0x12345678, result);
        result = Toolbox.readInt(source, 0, 8);
        assertEquals(0x8765432112345678L, result);
        result = Toolbox.readInt(source, 2, 4);
        assertEquals(0x43211234, result);
    }

    /**
     * Test of copyBytes method, of class Toolbox.
     */
    @Test
    public void testCopyBytes()
    {
        System.out.println("copyBytes");
        byte[] source = {0x78, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, (byte)0x87};
        byte[] expResult = {0x78, 0x56};
        byte[] result = Toolbox.copyBytes(source, 0, 2);
        assertArrayEquals(expResult, result);
        
        byte[] expResult2 = {0x34, 0x12, 0x21, 0x43};
        result = Toolbox.copyBytes(source, 2, 4);
        assertArrayEquals(expResult2, result);
    }

    /**
     * Test of bytesToString method, of class Toolbox.
     */
    @Test
    public void testBytesToString()
    {
        System.out.println("bytesToString");
        byte[] bytes = {0x7A, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, (byte)0x87};;
        String expResult = "7a56341221436587";
        String result = Toolbox.bytesToString(bytes);
        assertEquals(expResult, result);
    }

    /**
     * Test of intToBytes method, of class Toolbox.
     */
    @Test
    public void testIntToBytes()
    {
        System.out.println("intToBytes");
        long theInt = 0x1234L;
        int length = 2;
        byte[] expResult = {0x34, 0x12};
        byte[] result = Toolbox.intToBytes(theInt, length);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of concatenate method, of class Toolbox.
     */
    @Test
    public void testConcatenate()
    {
        System.out.println("concatenate");
        byte[] bytes1 = {'t', 'e', 's'};
        byte[] bytes2 = {'t'};
        byte[] expResult = {'t', 'e', 's', 't'};
        byte[] result = Toolbox.concatenate(bytes1, bytes2);
        assertArrayEquals(expResult, result);
    }
    
}
