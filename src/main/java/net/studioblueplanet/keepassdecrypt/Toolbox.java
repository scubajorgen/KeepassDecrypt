/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;



import java.io.IOException;
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
     * Calculates SHA256 hash
     * @param data Data to calculate hash about
     * @return The hash
     */
    public static byte[] sha512(byte[] data)
    {
        byte[] hash=null;
        try
        {
            MessageDigest digest    =MessageDigest.getInstance("SHA-512");            
            hash                    =digest.digest(data);
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.error("Algorithm error while calculating HMAC SHA512: {}", e.getMessage());
        }
        return hash;
    }    
    
    /**
     * Validates the hash of the data
     * @param data Data to test
     * @param hash Expected hash to use
     * @return True if validated.
     */
    public static boolean validateSha256Hash(byte[] data, byte[] hash)
    {
        boolean valid=true;
        byte[] blockHash=Toolbox.sha256(data);
        for(int i=0;i<blockHash.length && valid;i++)
        {
            if (blockHash[i]!=hash[i])
            {
                valid=false;
                LOGGER.error("Block hash invalid!");
            }
        }
        return valid;
    }    

    /**
     * Validates the HMAC SHA256 hash of the data
     * @param data Data to test
     * @param key Key for the HMAC SHA256
     * @param hash Expected hash to use
     * @return True if validated.
     */
    public static boolean validateHmacSha256Hash(byte[] data, byte[] key, byte[] hash)
    {
        boolean valid=true;
        byte[] blockHash        =Toolbox.hmacSha256(data, key);
        for(int i=0;i<blockHash.length && valid;i++)
        {
            if (blockHash[i]!=hash[i])
            {
                valid=false;
                LOGGER.error("Block hash invalid!");
            }
        }
        return valid;
    }    

    /**
     * Converts bytes to int
     * @param source Input byte array
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
     * @param source Input byte array
     * @param index Index in file data
     * @param length Number of bytes to copy
     * @return Array with copied bytes
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
    
    /**
     * Converts an integer to bytes, little endian
     * @param theInt The integer to convert
     * @param length The size of the integer, aka the number of bytes
     * @return 
     */
    public static byte[] intToBytes(long theInt, int length)
    {
        byte[] bytes=new byte[length];
        
        for (int i=0; i<length; i++)
        {
            bytes[i]=(byte)(theInt&0xff);
            theInt>>=8;
        }
        
        return bytes;
    }
    
    /**
     * Concatenate two byte arrays
     * @param bytes1 First array
     * @param bytes2 Second array
     * @return The concatenated byte arrays
     */
    public static byte[] concatenate(byte[] bytes1, byte[] bytes2)
    {
        int length=bytes1.length+bytes2.length;
        byte[] result=new byte[length];
        System.arraycopy(bytes1, 0, result, 0            , bytes1.length);
        System.arraycopy(bytes2, 0, result, bytes1.length, bytes2.length);
        return result;
    }
    
    /**
     * Decompress
     * @param gzip The gzip bytes to decompress
     * @return The decompressed payload
     */
    public static byte[] decompress(byte[] gzip)
    {
        byte[] buf = new byte[1024];
        byte[] uncompressed=null;
        try
        {
            // With 'gzip' being the compressed buffer
            java.io.ByteArrayInputStream bytein = new java.io.ByteArrayInputStream(gzip);
            java.util.zip.GZIPInputStream gzin = new java.util.zip.GZIPInputStream(bytein);
            java.io.ByteArrayOutputStream byteout = new java.io.ByteArrayOutputStream();
            int res = 0;
            
            while (res >= 0) 
            {
                res = gzin.read(buf, 0, buf.length);
                if (res > 0) 
                {
                    byteout.write(buf, 0, res);
                }
            }
            uncompressed = byteout.toByteArray();
            LOGGER.debug("Decompression succeeded, compressed {}, uncompressed {} bytes", gzip.length, uncompressed.length);
        }
        catch(IOException e)
        {
            LOGGER.error("Error decompressing GZIP payload: ", e.getMessage());
        }
        return uncompressed;
    }    
}
