/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

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
    private final static Logger     LOGGER = LogManager.getLogger(DatabaseDecrypter3.class);
    private DatabaseHeader          header;
    private byte[]                  encryptedDatabase;
    
    private byte[]                  masterKey;
    private byte[]                  decryptedPayload;       // File payload after decryption (32 bytes + blocks)
    private byte[]                  databaseBlocks;         // Database data containing the blocks
    private byte[]                  zippedDatabase;         // Blocks concatenated: gzip
    private byte[]                  unzippedDatabase;       // unzipped bytes of representing the database
    private String                  xmlDatabase;            // Database as XML string    
    
    /**
     * Initialize
     * @param header Header to use
     * @param encryptedDatabase The encrypted payload
     */
    public void initialize(DatabaseHeader header, byte[] encryptedDatabase)
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
            valid=decryptPayload();
            if (valid)
            {
                valid=validateDecryption();
                if (valid)
                {
                    valid=deblockify();
                    if (valid)
                    {
                        if (header.getCompressionFlags()==0x01)
                        {
                            unzippedDatabase=Toolbox.decompress(zippedDatabase);
                        }
                        else
                        {
                            unzippedDatabase=zippedDatabase;
                        }
                        xmlDatabase=new String(unzippedDatabase);
                    }
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
            valid=decryptPayloadAes();
            if (valid)
            {
                valid=validateDecryption();
            }
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
            if (streamStartBytes[i]!=decryptedPayload[i])
            {
                valid=false;
            }
        }
        return valid;
    }

    /**
     * Decrypt the database using Aes and the master key
     */
    private boolean decryptPayload()
    {
        boolean valid;
        if (Toolbox.bytesToString(header.getCipherUuid()).equals(DatabaseHeader.UUID_AESCBC))
        {
            valid=decryptPayloadAes();
        }
        else
        {
            LOGGER.error("Not supported cipher used");
            valid=false;
        }
        return valid;
    }
    
    
    /**
     * Decrypt the database using Aes and the master key
     */
    private boolean decryptPayloadAes()
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
            
            decryptedPayload    =cipher.doFinal(encryptedDatabase);
            valid               =true;
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
     * The payload before decompression consists is subdivided in blocks.
     * The hash of the blocks is tested and the blocks are glued together
     */
    private boolean deblockify()
    {
        int     index;
        int     totalSize;
        boolean valid;

        byte[] streamStartBytes=header.getStreamStartBytes();
        databaseBlocks=Toolbox.copyBytes(decryptedPayload, streamStartBytes.length, decryptedPayload.length-streamStartBytes.length);
        LOGGER.debug("Blocks length    {}", databaseBlocks.length);        
        
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
            if (size>0)
            {
                valid=Toolbox.validateSha256Hash(block, hash);
                System.arraycopy(block, 0, zippedDatabase, totalSize, size);
                totalSize+=size;
                index+=size;        
            }
        }
        return valid;
    }
}
