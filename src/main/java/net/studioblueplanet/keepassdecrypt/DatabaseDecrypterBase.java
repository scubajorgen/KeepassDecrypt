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
 * The methods that are applicable for KDBX 3.x and 4.x
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

    /**
     * Return the XML database as a string
     * @return The XML as string
     */
    @Override
    public String getXmlDatabase()
    {
        return this.xmlDatabase;
    }  
    
    /**
     * Based on the users password, create the transformed key and the 
     * master key. Note: this assumes only a password, not an windows account
     * and key from a keyfile.
     * @param password password
     * @return True if all went well
     */
    protected boolean generateMasterKey(String password)
    {
        byte[] compositeKey;
        boolean valid=false;
        
        // Generate compsitekey
        compositeKey    =Toolbox.sha256(password.getBytes(StandardCharsets.UTF_8));
        compositeKey    =Toolbox.sha256(compositeKey);

        // Generate the transformed key
        if (header.getKdfCipher()==null || header.getKdfCipher()==DatabaseHeader.Cipher.AESECB)
        {
            valid=transformAes(compositeKey);
        }
        else if (header.getKdfCipher()==DatabaseHeader.Cipher.ARGON2D)
        {
            valid=transformArgon(compositeKey, "d");
        }
        else if (header.getKdfCipher()==DatabaseHeader.Cipher.ARGON2ID)
        {
            valid=transformArgon(compositeKey, "id");
        }
        else
        {
            LOGGER.error("Unsupported KDF cipher");
        }        
        LOGGER.debug("Transformed Key    : {}", Toolbox.bytesToString(transformedKey));

        // Generate the master key
        byte[] masterSeed=header.getMasterSeed();
        byte[] c = new byte[masterSeed.length + transformedKey.length];
        System.arraycopy(masterSeed    , 0, c, 0                , masterSeed.length    );
        System.arraycopy(transformedKey, 0, c, masterSeed.length, transformedKey.length);            
        masterKey=Toolbox.sha256(c);
        LOGGER.debug("Master Key         : {}", Toolbox.bytesToString(masterKey));

        return valid;
    }
    
    /**
     * Transform the composite key based on a number of AES ECB rounds using
     * the transform seed as key
     * @param key The key to transform
     * @return True if all went well
     */
    private boolean transformAes(byte[] key)
    {
        boolean valid;
        valid=false;
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec keySpec=new SecretKeySpec(header.getKdfTransformSeed(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            transformedKey=key;
            LOGGER.debug("Transformed Key    : {}", Toolbox.bytesToString(transformedKey));
            for (int i=0; i<header.getKdfTransformRounds(); i++)
            {
                transformedKey=cipher.doFinal(transformedKey);
            }
            transformedKey=Toolbox.sha256(transformedKey);

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
     * Transform the composite key based on the argon algorithms
     * @param key The key to transform
     * @return True if all went well
     */
    private boolean transformArgon(byte[] key, String argonType)
    {
        boolean valid=true;

        int memory      =(int)(header.getKdfMemorySize()/1024L);
        int iterations  =(int)header.getKdfIterations();
        int parallelism =header.getKdfParallelism();
        int version     =header.getKdfVersion();
        
        Argon2Function.Argon2 param;
        if (argonType.equals("d"))
        {
            param=Argon2Function.Argon2.D;
        }
        else if (argonType.equals("i"))
        {
            param=Argon2Function.Argon2.I;
        }
        else
        {
            param=Argon2Function.Argon2.ID;
        }

        // First try, password4j: does not work with rawnbyte arrays!!!
        Argon2Function cipher=Argon2Function.getInstance(memory, iterations, parallelism, 32, param, version);
        transformedKey=cipher.hash(key, header.getKdfTransformSeed());

        return valid;
    }    

    /**
     * Decrypt the payload
     * @param payload Payload to decrypt
     * @return True if successful, false if not
     */
    protected boolean decryptPayload(byte[] payload)
    {
        boolean valid=true;
        
        if (header.getPayloadCipher()==DatabaseHeader.Cipher.AESCBC)
        {
            valid=decryptPayloadAes(payload);
        }
        else if (header.getPayloadCipher()==DatabaseHeader.Cipher.CHACHA20)
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
     * @param payload Payload to decrypt
     * @return True if successful, false if not
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
     * @param payload Payload to decrypt
     * @return True if successful, false if not
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
