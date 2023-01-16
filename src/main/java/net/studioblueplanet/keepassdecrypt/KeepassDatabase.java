/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * Keepass database decryption
 * @author jorgen
 */
public class KeepassDatabase
{
    private final static Logger LOGGER = LogManager.getLogger(KeepassDatabase.class);

    // Header fields
    private byte[]              cipherUuid;
    private byte[]              masterSeed;
    private byte[]              transformSeed;
    private byte[]              encryptionIv;
    private byte[]              passwordEncryptionKey;
    private byte[]              streamStartBytes;
    private byte[]              endOfHeader;
    private byte[]              masterKey;
    private int                 signature1;
    private int                 signature2;
    private int                 compressionFlags;
    private long                transformRounds;
    private int                 randomStreamId;
    
    // Intermediate and final process result
    private byte[]              filedata;               // raw file bytes
    private byte[]              encryptedDatabase;      // The part of the file containing the database data
    private byte[]              decryptedDatabase;      // Database data after decryption
    private byte[]              databaseBlocks;         // Database data containing the zipped blocks
    private byte[]              zippedDatabase;         // Blocks concatenated: gzip
    private byte[]              unzippedDatabase;       // unzipped bytes of representing the database
    String                      xmlDatabase;            // Database as XML string
    
    
            
    /**
     * Constructor. Reads and parses the information in the kdbx file
     * @param filename Filename of the kdbx file
     */
    public KeepassDatabase(String filename)
    {
        Path path = Paths.get(filename);
        
        try
        {
            filedata = Files.readAllBytes(path);
            parseData();
        }
        catch (IOException e)
        {
            LOGGER.error("Error reading file {}: {}", filename, e.getMessage());
        }
    }
    
    /**
     * Decrypt the database using the password given
     * @param password Password to use for decrypting
     * @return The Database XML as string
     */
    public String decryptDatabase(String password)
    {
        boolean valid;
        
        xmlDatabase=null;
        valid=generateKey(password);
        if (valid)
        {
            valid=decryptDatabase();
            if (valid)
            {
                valid=deblockify();
                if (valid)
                {
                    if (compressionFlags==0x01)
                    {
                        unzippedDatabase=decompress(zippedDatabase);
                    }
                    else
                    {
                        unzippedDatabase=zippedDatabase;
                    }
                    xmlDatabase=new String(unzippedDatabase);
                }
            }
        }
        return xmlDatabase;
    }
    
    /**
     * This method tries a password. It checks whether it results in
     * properly decrypted data
     * @param password Password to test
     * @return True if the password is valid, false if not
     */
    public boolean testPassword(String password)
    {
        boolean valid;
        
        valid=generateKey(password);
        if (valid)
        {
            valid=decryptDatabase();
        }
        return valid;
    }
    
    /**
     * Converts bytes to int
     * @param index Index in the array of the bytes to convert
     * @param length Number of bytes to convert, max 8
     * @return The integer
     */
    private long readInt(byte[] source, int index, int length)
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
    private byte[] copyBytes(byte[] source, int index, int length)
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
     * Processes the file data into sensible things
     */
    private void parseData()
    {
        int     index;
        byte    type;
        int     length;
        
        
        LOGGER.info("Parsing data");
        signature1=(int)readInt(filedata, 0, 4);
        signature2=(int)readInt(filedata, 4, 4);
        
        index   =8;
        type    =-1;
        while (type!=0x00)
        {
            type    =filedata[index];
            length  =(int)readInt(filedata, index+1, 2);
            switch(type)
            {
                default:
                    index+=length+3;
                    break;
                case 0x00:
                    endOfHeader             =copyBytes(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x01:
                    index+=4;
                    break;
                case 0x02:
                    cipherUuid              =copyBytes(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x03:
                    compressionFlags        =(int)readInt(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x04:
                    masterSeed              =copyBytes(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x05:
                    transformSeed           =copyBytes(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x06:
                    transformRounds         =readInt(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x07:
                    encryptionIv            =copyBytes(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x08:
                    passwordEncryptionKey   =copyBytes(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x09:
                    streamStartBytes        =copyBytes(filedata, index+3, length);
                    index+=length+3;
                    break;
                case 0x0a:
                    randomStreamId          =(int)readInt(filedata, index+3, length);
                    index+=length+3;
                    break;
            }
        }
        
        if ((filedata.length-index)%16>0)
        {
            LOGGER.error("Invalid encrypted database size");
            System.exit(0);
        }
        encryptedDatabase=copyBytes(filedata, index, filedata.length-index);
        LOGGER.info("Encrypted database length: {}", encryptedDatabase.length);
    }
    
    /** 
     * Generate the master decryption/encryption key based on the password
     * @param password Password
     */
    private boolean generateKey(String password)
    {
        boolean valid;
        valid=false;
        try
        {
            MessageDigest digest    =MessageDigest.getInstance("SHA-256");
            byte[] compositeKey     =digest.digest(password.getBytes(StandardCharsets.UTF_8));
            compositeKey            =digest.digest(compositeKey);
            

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec key=new SecretKeySpec(transformSeed, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            

            byte[] transformedKey=compositeKey;
            LOGGER.debug("Transformed Key    : {}", bytesToString(transformedKey));
            for (int i=0; i<transformRounds; i++)
            {
                transformedKey=cipher.doFinal(transformedKey);
            }
            transformedKey=digest.digest(transformedKey);
            LOGGER.debug("Transformed Key    : {}", bytesToString(transformedKey));

            
            byte[] c = new byte[masterSeed.length + transformedKey.length];
            System.arraycopy(masterSeed    , 0, c, 0                , masterSeed.length    );
            System.arraycopy(transformedKey, 0, c, masterSeed.length, transformedKey.length);            
            
            masterKey=digest.digest(c);
            LOGGER.debug("Master Key         : {}", bytesToString(masterKey));
            valid=true;
         
            
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.error("Error generating keys: No such algo: {}", e.getMessage());
        }
        catch (NoSuchPaddingException e)
        {
            LOGGER.error("Error generating keys: No such padding: {}", e.getMessage());
        }
        catch (InvalidKeyException e)
        {
            LOGGER.error("Error generating keys : Invalid Key: {}", e.getMessage());
        }
        catch (IllegalBlockSizeException e)
        {
            LOGGER.error("Error generating keys : Illegal block size: {}", e.getMessage());
        }
        catch (BadPaddingException e)
        {
            LOGGER.error("Error generating keys : Bad Padding: {}", e.getMessage());
        }
        return valid;
    }
    
    private boolean validateDecryption()
    {
        boolean valid=true;
        
        for(int i=0; i<streamStartBytes.length; i++)
        {
            if (streamStartBytes[i]!=decryptedDatabase[i])
            {
                valid=false;
            }
        }
        return valid;
    }
    
    
    /**
     * Decrypt the database using the master key
     */
    private boolean decryptDatabase()
    {
        boolean valid;
        valid=false;
        try
        {
            Cipher cipher       = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key   =new SecretKeySpec(masterKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encryptionIv));
            
            decryptedDatabase   =cipher.doFinal(encryptedDatabase);
            
            if (validateDecryption())
            {
                LOGGER.debug("Decrypted length {}", decryptedDatabase.length);
                databaseBlocks=copyBytes(decryptedDatabase, streamStartBytes.length, decryptedDatabase.length-streamStartBytes.length);
                LOGGER.debug("Blocks length    {}", databaseBlocks.length);
                valid=true;
            }
            else
            {
                LOGGER.error("Decryption failed");
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.error("Error decrypting database: No such algo: {}", e.getMessage());
        }
        catch (NoSuchPaddingException e)
        {
            LOGGER.error("Error gdecrypting database: No such padding: {}", e.getMessage());
        }
        catch (InvalidKeyException e)
        {
            LOGGER.error("Error decrypting database : Invalid Key: {}", e.getMessage());
        }
        catch (IllegalBlockSizeException e)
        {
            LOGGER.error("Error decrypting database: Illegal block size: {}", e.getMessage());
        }
        catch (BadPaddingException e)
        {
            LOGGER.error("Error decrypting database: Bad Padding: {}", e.getMessage());
        }
        catch (InvalidAlgorithmParameterException e)
        {
            LOGGER.error("Error decrypting database: Invalid parameter: {}", e.getMessage());
        }
        return valid;
    }

    /**
     * Validates the hash of the block
     * @param block Block to test
     * @param hash Hash to use
     * @return True if validated.
     */
    private boolean validateBlock(byte[] block, byte[] hash)
    {
        boolean valid=true;

        try
        {
            MessageDigest digest    =MessageDigest.getInstance("SHA-256");
            byte[] blockHash        =digest.digest(block);
            for(int i=0;i<blockHash.length && valid;i++)
            {
                if (blockHash[i]!=hash[i])
                {
                    valid=false;
                    LOGGER.error("Block hash invalid!");
                }
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.error("Error validating blockhash: No such algo: {}", e.getMessage());
        }
       
        return true;
    }
    
    /**
     * The payload before decompression consists is subdivided in blocks.
     * The hash of the blocks is tested and the blocks are glued together
     */
    private boolean deblockify()
    {
        int     index;
        int     totalSize;
        boolean valid;

        
        index=0;
        totalSize=0;
        while (index<databaseBlocks.length)
        {
            int id=(int)readInt(databaseBlocks, index, 4);
            index+=4;
            index+=32;
            int size=(int)readInt(databaseBlocks, index, 4);
            index+=4;
            totalSize+=size;
            LOGGER.info("ID: {}, size {}", id, size);
            index+=size;
            
        }
        
        zippedDatabase=new byte[totalSize];
        index=0;
        totalSize=0;
        valid=true;
        while (index<databaseBlocks.length && valid)
        {
            int id=(int)readInt(databaseBlocks, index, 4);
            index+=4;
            byte[] hash=copyBytes(databaseBlocks, index, 32);
            index+=32;
            int size=(int)readInt(databaseBlocks, index, 4);
            index+=4;
            
            byte[] block=copyBytes(databaseBlocks, index, size);
            
            valid=validateBlock(block, hash);
            
            System.arraycopy(block, 0, zippedDatabase, totalSize, size);

            totalSize+=size;
            index+=size;            
        }
        return valid;
    }
    
    private byte[] decompress(byte[] gzip)
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
        }
        catch(IOException e)
        {
            LOGGER.error("Error decompressing: ", e.getMessage());
        }
        return uncompressed;
    }

    
    /**
     * Pretty print bytes to string
     * @param bytes Bytes to print
     * @return The string
     */
    private String bytesToString(byte[] bytes)
    {
        String byteString="";
        
        for (int i=0; i<bytes.length; i++)
        {
            byteString+=String.format("%02x", bytes[i]);
        }
        return byteString;
    }
    
    public void dumpData()
    {
        LOGGER.info("Header Signature 1   : {}", String.format("%x", signature1));
        LOGGER.info("Header Signature 2   : {}", String.format("%x", signature2));
        LOGGER.info("2 Cipher UUID        : {}", bytesToString(cipherUuid));
        LOGGER.info("3 Compression flags  : {}", compressionFlags);
        LOGGER.info("4 Master Seed        : {}", bytesToString(masterSeed));
        LOGGER.info("5 Transform Seed     : {}", bytesToString(transformSeed));
        LOGGER.info("6 Transform rounds   : {}", transformRounds);
        LOGGER.info("7 Encryption IV      : {}", bytesToString(encryptionIv));
        LOGGER.info("8 Password Encr. key : {}", bytesToString(passwordEncryptionKey));
        LOGGER.info("9 Stream start bytes : {}", bytesToString(streamStartBytes));
        LOGGER.info("A Random Stream ID   : {}", randomStreamId);
        LOGGER.info("0 End of header      : {}", bytesToString(endOfHeader));
    }
    
}
