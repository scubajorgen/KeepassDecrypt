/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;



import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author jorgen
 */
public class Toolbox
{
    private final static Logger LOGGER = LogManager.getLogger(KeepassDatabase.class);
    
    /**
     * Calculates HMAC SHA256 hash
     * @param data Data to calculate hash 
     * @param key Key to use
     * @return HMAC SHA256 hash
     */
    public static byte[] hmacSha256(byte[] data, byte[] key)
    {
        byte[] hash=null;
        
        try
        {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            hash=mac.doFinal(data);
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.error("Algorithm error while calculating HMAC SHA256: {}", e.getMessage());
        }
        catch (InvalidKeyException e)
        {
            LOGGER.error("Key error while calculating HMAC SHA256: {}", e.getMessage());
        }
        return hash;
    }
    
    /**
     * Calculates SHA256 hash
     * @param data Data to calculate hash about
     * @return The hash
     */
    public static byte[] sha256(byte[] data)
    {
        byte[] hash=null;
        try
        {
            MessageDigest digest    =MessageDigest.getInstance("SHA-256");
            hash                    =digest.digest(data);
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.error("Algorithm error while calculating HMAC SHA256: {}", e.getMessage());
        }
        return hash;
    }

    /**
     * Converts bytes to int
     * @param index Index in the array of the bytes to convert
     * @param length Number of bytes to convert, max 8
     * @return The integer
     */
    public static long readInt(byte[] source, int index, int length)
    {
        long    theInt;
        int     i;
        
        i       =0;
        theInt  =0;
        while (i<length)
        {
            theInt <<= 8;
            theInt |= (source[index+length-1-i]&0xFF);
            i++;
        }
        return theInt;
    }
    
    /** 
     * Allocates space and copies bytes from the file data
     * @param index Index in file data
     * @param length Number of bytes to copy
     */
    public static byte[] copyBytes(byte[] source, int index, int length)
    {
        int     i;
        byte[]  target;
        
        target=new byte[length];
        i=0;
        while (i<length)
        {
            target[i]=source[index+i];
            i++;
        }
        return target;
    }    
    
    /**
     * Pretty print bytes to string
     * @param bytes Bytes to print
     * @return The string
     */
    public static String bytesToString(byte[] bytes)
    {
        String byteString="";
        if (bytes!=null)
        {
            for (int i=0; i<bytes.length; i++)
            {
                byteString+=String.format("%02x", bytes[i]);
            }
        }
        else
        {
            byteString="-";
        }
        return byteString;
    }    
}
