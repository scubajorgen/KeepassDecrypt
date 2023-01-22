/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author jorgen
 */
public class DatabaseDecrypter3 implements DatabaseDecrypter
{
    private final static Logger     LOGGER = LogManager.getLogger(KeepassDatabase.class);
    private final DatabaseHeader    header;
    private final byte[]            encryptedDatabase;
    
    private byte[]                  masterKey;
    private byte[]                  decryptedDatabase;      // Database data after decryption
    private byte[]                  databaseBlocks;         // Database data containing the zipped blocks
    private byte[]                  zippedDatabase;         // Blocks concatenated: gzip
    private byte[]                  unzippedDatabase;       // unzipped bytes of representing the database
    private String                  xmlDatabase;            // Database as XML string    
    
    
    public DatabaseDecrypter3(DatabaseHeader header, byte[] encryptedDatabase)
    {
        this.header             =header;
        this.encryptedDatabase  =encryptedDatabase;        
    }
    
    /**
     * Decrypt the database using the password given. 
     * @param password Password to use for decrypting
     * @return The Database XML as string
     */
    @Override
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
                    if (header.getCompressionFlags()==0x01)
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
    @Override
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
    
    public String getXmlDatabase()
    {
        return this.xmlDatabase;
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
            byte[] compositeKey=Toolbox.sha256(password.getBytes(StandardCharsets.UTF_8));
            compositeKey=Toolbox.sha256(compositeKey);

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec key=new SecretKeySpec(header.getTransformSeed(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            

            byte[] transformedKey=compositeKey;
            LOGGER.debug("Transformed Key    : {}", Toolbox.bytesToString(transformedKey));
            for (int i=0; i<header.getTransformRounds(); i++)
            {
                transformedKey=cipher.doFinal(transformedKey);
            }
            transformedKey=Toolbox.sha256(transformedKey);
            LOGGER.debug("Transformed Key    : {}", Toolbox.bytesToString(transformedKey));

            
            byte[] masterSeed=header.getMasterSeed();
            byte[] c = new byte[masterSeed.length + transformedKey.length];
            System.arraycopy(masterSeed    , 0, c, 0                , masterSeed.length    );
            System.arraycopy(transformedKey, 0, c, masterSeed.length, transformedKey.length);            
            
            masterKey=Toolbox.sha256(c);
            LOGGER.debug("Master Key         : {}", Toolbox.bytesToString(masterKey));
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
    
    /**
     * Validate the decryption result by checking it with the unencrypted start bytes
     * in the header. 
     * @return True if valid.
     */
    private boolean validateDecryption()
    {
        boolean valid=true;
        
        byte[] streamStartBytes=header.getStreamStartBytes();
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
     * Decrypt the database using Aes and the master key
     */
    private boolean decryptDatabase()
    {
        boolean valid;
        valid=false;

        if ((encryptedDatabase.length)%16>0)
        {
            LOGGER.error("Invalid encrypted database size");
            System.exit(0);
        }        
        
        try
        {
            Cipher cipher       = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key   =new SecretKeySpec(masterKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(header.getEncryptionIv()));
            
            decryptedDatabase   =cipher.doFinal(encryptedDatabase);
            
            if (validateDecryption())
            {
                byte[] streamStartBytes=header.getStreamStartBytes();
                LOGGER.debug("Decrypted length {}", decryptedDatabase.length);
                databaseBlocks=Toolbox.copyBytes(decryptedDatabase, streamStartBytes.length, decryptedDatabase.length-streamStartBytes.length);
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
        byte[] blockHash        =Toolbox.sha256(block);
        for(int i=0;i<blockHash.length && valid;i++)
        {
            if (blockHash[i]!=hash[i])
            {
                valid=false;
                LOGGER.error("Block hash invalid!");
            }
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
            int id=(int)Toolbox.readInt(databaseBlocks, index, 4);
            index+=4;
            index+=32;
            int size=(int)Toolbox.readInt(databaseBlocks, index, 4);
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
            int id=(int)Toolbox.readInt(databaseBlocks, index, 4);
            index+=4;
            byte[] hash=Toolbox.copyBytes(databaseBlocks, index, 32);
            index+=32;
            int size=(int)Toolbox.readInt(databaseBlocks, index, 4);
            index+=4;
            
            byte[] block=Toolbox.copyBytes(databaseBlocks, index, size);
            
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
}
