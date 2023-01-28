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
public abstract class DatabaseDecrypterBase implements DatabaseDecrypter
{
    private final static Logger     LOGGER = LogManager.getLogger(DatabaseDecrypter3.class);
    protected DatabaseHeader        header;
    protected byte[]                filePayload;
    protected byte[]                transformedKey;
    protected byte[]                masterKey;
    protected String                xmlDatabase;            // Database as XML string 
    protected byte[]                decryptedPayload;       // File payload after decryption (32 bytes + blocks)
    /**
     * Initializes the decrypter
     * @param header The processed file header
     * @param encryptedDatabase The encrypted payload of the file
     */
    @Override
    public void initialize(DatabaseHeader header, byte[] encryptedDatabase)
    {
        this.header             =header;
        this.filePayload        =encryptedDatabase;        
    }    

  
    
    protected boolean generateMasterKey(String password, long rounds, byte[] seed)
    {
        boolean     valid;
        
        valid=true;       
        valid=generateMasterKeyAes(password, rounds, seed);

        return valid;
    }
    
    
    /** 
     * Generate the master decryption/encryption key based on the password
     * @param password Password
     */
    private boolean generateMasterKeyAes(String password, long rounds, byte[] seed)
    {
        boolean valid;
        valid=false;
        try
        {
            byte[] compositeKey=Toolbox.sha256(password.getBytes(StandardCharsets.UTF_8));
            compositeKey=Toolbox.sha256(compositeKey);

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec key=new SecretKeySpec(seed, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            transformedKey=compositeKey;
            LOGGER.debug("Transformed Key    : {}", Toolbox.bytesToString(transformedKey));
            for (int i=0; i<rounds; i++)
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
    
    public String getXmlDatabase()
    {
        return this.xmlDatabase;
    }    

  
    protected boolean decryptPayload(byte[] payload)
    {
        boolean valid=true;
        
        if (Toolbox.bytesToString(header.getCipherUuid()).equals(DatabaseHeader.UUID_AESCBC))
        {
            valid=decryptPayloadAes(payload);
        }
        else if (Toolbox.bytesToString(header.getCipherUuid()).equals(DatabaseHeader.UUID_CHACHA20))
        {
            valid=decryptPayloadChaCha(payload);
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
    private boolean decryptPayloadAes(byte[] payload)
    {
        boolean valid;
        valid=false;

        if ((filePayload.length)%16>0)
        {
            LOGGER.error("Invalid encrypted database size");
            System.exit(0);
        }        
        
        try
        {
            Cipher cipher       = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key   =new SecretKeySpec(masterKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(header.getEncryptionIv()));
            
            decryptedPayload    =cipher.doFinal(payload);
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
     * Decrypt the database using ChaCha and the master key
     */
    private boolean decryptPayloadChaCha(byte[] payload)
    {
        boolean valid=false;
        
        byte[] nonce=header.getEncryptionIv();

        try
        {
            ChaCha20 cipher =new ChaCha20(masterKey, nonce, 0);
            decryptedPayload=new byte[payload.length];
            cipher.decrypt(decryptedPayload, payload, payload.length);
            valid           =true;
        }
        catch(ChaCha20.WrongKeySizeException e)
        {
            LOGGER.error("Wrong key size in ChaCha decrypt");
        }
        catch(ChaCha20.WrongNonceSizeException e)
        {
            LOGGER.error("Wrong nonce size in ChaCha decrypt");
        }
        return valid;
    }    

}
