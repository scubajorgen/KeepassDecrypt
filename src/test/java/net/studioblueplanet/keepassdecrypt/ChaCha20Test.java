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
public class ChaCha20Test
{
    
    public ChaCha20Test()
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
     * Test of streamingDecrypt method, of class ChaCha20.
     */
    @Test
    public void testStreamingDecrypt_byteArr_int() throws Exception
    {
        System.out.println("streamingDecrypt/streamingEncrypt");
        byte[] src = "Password".getBytes();
        int len = 8;
        byte[] key  =new byte[32];
        byte[] nonce=new byte[12];
        
        ChaCha20 encryptInstance = new ChaCha20(key, nonce, 0);
        byte[] expResult = {38, -39, -109, -34, -41, -98, 79, -12};
        byte[] result = encryptInstance.streamingEncrypt(src, len);
        assertArrayEquals(expResult, result);
        
        ChaCha20 decryptInstance = new ChaCha20(key, nonce, 0);
        result = decryptInstance.streamingDecrypt(result, len);
        assertArrayEquals(src, result);

        src = "Test1234".getBytes();
        byte[] expResult2 = {20, 56, 25, -111, 98, -76, -114, 28};
        result = encryptInstance.streamingEncrypt(src, len);
        assertArrayEquals(expResult2, result);

        result = decryptInstance.streamingDecrypt(result, len);
        assertArrayEquals(src, result);

        src = "PasswordTest1234".getBytes();
        encryptInstance = new ChaCha20(key, nonce, 0);
        byte[] expResult3 = Toolbox.concatenate(expResult, expResult2);
        result = encryptInstance.streamingEncrypt(src, 16);
        assertArrayEquals(expResult3, result);

        decryptInstance = new ChaCha20(key, nonce, 0);
        result = decryptInstance.streamingDecrypt(result, 16);
        assertArrayEquals(src, result);

    }

    /**
     * Test of streamingDecrypt method, of class ChaCha20.
     */
    @Test
    public void testStreamingDecrypt_byteArr_int2() throws Exception
    {
        System.out.println("streamingDecrypt/streamingEncrypt");
        ChaCha20 encryptInstance;
        byte[] src;
        byte[] fullResult;
        byte[] result1;
        byte[] result2;
        byte[] result3;
        byte[] test;
        byte[] key  =new byte[32];
        byte[] nonce=new byte[12];

        encryptInstance = new ChaCha20(key, nonce, 0);
        src = "PasswordPasswordPasswordPasswordPasswordPasswordPasswordPassword2".getBytes();   // 65 bytes
        fullResult = encryptInstance.streamingEncrypt(src, src.length);

        encryptInstance = new ChaCha20(key, nonce, 0);
        src = "PasswordPasswordPasswordPasswordPasswordPasswordPasswordPasswor".getBytes();     // 63 bytes
        result1 = encryptInstance.streamingEncrypt(src, src.length);
        src = "d2".getBytes();                                                                  // 2 bytes
        result2 = encryptInstance.streamingEncrypt(src, src.length);
        test=Toolbox.concatenate(result1, result2);
        assertArrayEquals(fullResult, test);


        encryptInstance = new ChaCha20(key, nonce, 0);
        src = "PasswordPasswordPasswordPasswordPasswordPasswordPasswordPassword2".getBytes();   
        fullResult = encryptInstance.streamingEncrypt(src, src.length);

        encryptInstance = new ChaCha20(key, nonce, 0);
        src = "PasswordPassword".getBytes();
        result1 = encryptInstance.streamingEncrypt(src, src.length);
        src = "PasswordPasswordPasswordPasswordPasswordPasswor".getBytes();
        result2 = encryptInstance.streamingEncrypt(src, src.length);
        src = "d2".getBytes();
        result3 = encryptInstance.streamingEncrypt(src, src.length);
        test=Toolbox.concatenate(result1, result2);
        test=Toolbox.concatenate(test, result3);
        assertArrayEquals(fullResult, test);
        
        encryptInstance = new ChaCha20(key, nonce, 0);
        src = ("PasswordPasswordPasswordPasswordPasswordPasswordPasswordPassword"+
               "PasswordPasswordPasswordPasswordPasswordPasswordPasswordPassword").getBytes();  //128 bytes
        fullResult = encryptInstance.streamingEncrypt(src, src.length);

        encryptInstance = new ChaCha20(key, nonce, 0);
        src = "PasswordPasswordPasswordPasswordPasswordPasswordPasswordPasswor".getBytes();
        result1 = encryptInstance.streamingEncrypt(src, src.length);
        src = "dPasswordPasswordPasswordPasswordPasswordPasswordPasswordPassword".getBytes();
        result2 = encryptInstance.streamingEncrypt(src, src.length);
        test=Toolbox.concatenate(result1, result2);
        assertArrayEquals(fullResult, test);
        
        encryptInstance = new ChaCha20(key, nonce, 0);
        src = "PasswordPasswordPasswordPasswordPasswordPasswordPasswordPassword".getBytes();
        result1 = encryptInstance.streamingEncrypt(src, src.length);
        src = "PasswordPasswordPasswordPasswordPasswordPasswordPasswordPassword".getBytes();
        result2 = encryptInstance.streamingEncrypt(src, src.length);
        test=Toolbox.concatenate(result1, result2);
        assertArrayEquals(fullResult, test);
        
        encryptInstance = new ChaCha20(key, nonce, 0);
        src = "PasswordPasswordPasswordPasswordPasswordPasswordPasswordPasswordP".getBytes();
        result1 = encryptInstance.streamingEncrypt(src, src.length);
        src = "asswordPasswordPasswordPasswordPasswordPasswordPasswordPassword".getBytes();
        result2 = encryptInstance.streamingEncrypt(src, src.length);
        test=Toolbox.concatenate(result1, result2);
        assertArrayEquals(fullResult, test);
    }
    
    
    
    /**
     * Test of decrypt method, of class ChaCha20.
     */
    @Test
    public void testDecrypt_byteArr_int() throws Exception
    {
        System.out.println("decrypt/encrypt");
        byte[] src = "Password".getBytes();
        int len = 8;
        byte[] key  =new byte[32];
        byte[] nonce=new byte[12];
        
        ChaCha20 encryptInstance = new ChaCha20(key, nonce, 0);
        byte[] expResult = {38, -39, -109, -34, -41, -98, 79, -12};
        byte[] result = encryptInstance.encrypt(src, len);
        assertArrayEquals(expResult, result);
        
        ChaCha20 decryptInstance = new ChaCha20(key, nonce, 0);
        result = decryptInstance.decrypt(result, len);
        assertArrayEquals(src, result);

        src = "Test1234".getBytes();
        byte[] expResult2 = {-53, 98, -108, -54, 100, 99, 11, 78};
        result = encryptInstance.encrypt(src, len);
        assertArrayEquals(expResult2, result);

        result = decryptInstance.decrypt(result, len);
        assertArrayEquals(src, result);

        src = "PasswordTest1234".getBytes();
        encryptInstance = new ChaCha20(key, nonce, 0);
        byte[] expResult3 = {38, -39, -109, -34, -41, -98, 79, -12,
                             20, 56, 25, -111, 98, -76, -114, 28};
        result = encryptInstance.encrypt(src, 16);
        assertArrayEquals(expResult3, result);

        decryptInstance = new ChaCha20(key, nonce, 0);
        result = decryptInstance.decrypt(result, 16);
        assertArrayEquals(src, result);
    }
    
}
