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
 * This class decrypts KDBX v4 files
 * @author jorgen
 */
public class DatabaseDecrypter4 implements DatabaseDecrypter
{
    private final static Logger     LOGGER = LogManager.getLogger(DatabaseDecrypter4.class);
    private DatabaseHeader          header;
    private DatabaseHeader          innerHeader;
    private byte[]                  blockedPayload;
    private byte[]                  encryptedPayload;
    private byte[]                  decryptedPayload;
    private byte[]                  unzippedPayload;
    private byte[]                  database;
    private byte[]                  transformedKey;
    private byte[]                  masterKey;
    private byte[]                  pbHmacKey;
    private byte[]                  streamStartBytes;
    private String                  xmlDatabase;
    
    /**
     * Initializes the decrypter
     * @param header The processed file header
     * @param encryptedDatabase The encrypted payload of the file
     */
    @Override
    public void initialize(DatabaseHeader header, byte[] encryptedDatabase)
    {
        this.header             =header;
        this.blockedPayload     =encryptedDatabase;        
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
        
        generateMasterKey(password);
        
        
        byte[] a            =Toolbox.concatenate(header.getMasterSeed(), transformedKey);
        byte[] b            ={1};
        byte[] c            =Toolbox.concatenate(a, b);
        pbHmacKey           =Toolbox.sha512(c);        

        byte[] headerHmacKey      =getHmacKey(0xffffffffffffffffL, pbHmacKey);
        
        valid=header.validateHmacHash(headerHmacKey);
        
        if (valid)
        {
            valid=deblockify();
            if (valid)
            {
                valid=decryptPayload();
                if (valid)
                {
                    processDecryptedPayload();
                }
            }
        }
        
        return this.xmlDatabase;
    }
    
    /**
     * Returns the key to be used for 
     * @param index
     * @param pbHmacKey64
     * @return 
     */
    private byte[] getHmacKey(long index, byte[] pbHmacKey64)
    {
        byte[] indexBytes   =Toolbox.intToBytes(index, 8);
        byte[] c            =Toolbox.concatenate(indexBytes, pbHmacKey64);
        byte[] hmacKey      =Toolbox.sha512(c);  
        return hmacKey;
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
        return true;
    }    
    
    /**
     * Return the database as XML string
     * @return The database
     */
    @Override
    public String getXmlDatabase()
    {
        return null;
    }
    
    
    private boolean generateMasterKey(String password)
    {
        boolean     valid;
        
        valid=true;       
        valid=generateMasterKeyAes(password);

        return valid;
    }
    
    
    /** 
     * Generate the master decryption/encryption key based on the password
     * @param password Password
     */
    private boolean generateMasterKeyAes(String password)
    {
        boolean valid;
        valid=false;
        try
        {
            byte[] compositeKey=Toolbox.sha256(password.getBytes(StandardCharsets.UTF_8));
            compositeKey=Toolbox.sha256(compositeKey);

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec key=new SecretKeySpec(header.getKdfTransformSeed(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            transformedKey=compositeKey;
            LOGGER.debug("Transformed Key    : {}", Toolbox.bytesToString(transformedKey));
            for (int i=0; i<header.getKdfTransformRounds(); i++)
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
     * The encrypted database contains of blocks. This method validates the 
     * hash of the blocks and glues the blocks together.
     * @return True if no error occurred, false if checks failed
     */
    private boolean deblockify()
    {
        boolean valid;
        long    i;
        byte[]  hash;
        byte[]  block;
        int     length;
        int     index;
        int     totalLength;
       
        
        // Calculate total payload length;
        index=0;
        totalLength=0;
        while (index<blockedPayload.length)
        {
            index+=32;
            length=(int)Toolbox.readInt(blockedPayload, index, 4);
            totalLength+=length;
            index+=4;
            index+=length;
        }
        
        encryptedPayload=new byte[totalLength];
        i=0;
        index=0;
        totalLength=0;
        valid=true;
        while (index<blockedPayload.length && valid)
        {
            hash=Toolbox.copyBytes(blockedPayload, index, 32);
            index+=32;
            
            length=(int)Toolbox.readInt(blockedPayload, index, 4);
            index+=4;
            System.arraycopy(blockedPayload, index, encryptedPayload, totalLength, length);
            if (length>0)
            {
                index+=length;
                totalLength+=length;

                byte[] sequenceNumber   =Toolbox.intToBytes(i, 8);
                byte[] lengthBytes      =Toolbox.intToBytes(length, 4);
                byte[] blockConcat      =Toolbox.concatenate(sequenceNumber, lengthBytes);
                blockConcat             =Toolbox.concatenate(blockConcat, encryptedPayload);

                byte[] blockHmacKey     =Toolbox.sha512(Toolbox.concatenate(sequenceNumber, pbHmacKey));            
                valid=Toolbox.validateHmacSha256Hash(blockConcat, blockHmacKey, hash);
            }
            i++;
        }
        return valid;
    }
    
    private boolean decryptPayload()
    {
        boolean valid=true;
        
        if (Toolbox.bytesToString(header.getCipherUuid()).equals(DatabaseHeader.UUID_AESCBC))
        {
            decryptPayloadAes();
        }
        else if (Toolbox.bytesToString(header.getCipherUuid()).equals(DatabaseHeader.UUID_CHACHA20))
        {
            decryptPayloadChaCha();
        }    
        return true;
    }
    
    /**
     * Decrypt the database using Aes and the master key
     */
    private boolean decryptPayloadAes()
    {
        boolean valid;
        valid=false;

        if ((blockedPayload.length)%16>0)
        {
            LOGGER.error("Invalid encrypted database size");
            System.exit(0);
        }        
        
        try
        {
            Cipher cipher       = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key   =new SecretKeySpec(masterKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(header.getEncryptionIv()));
            
            decryptedPayload   =cipher.doFinal(encryptedPayload);
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
    private boolean decryptPayloadChaCha()
    {
        boolean valid;
        valid=false;

        
        byte[] nonce=header.getEncryptionIv();

        try
        {
            ChaCha20 cipher=new ChaCha20(masterKey, nonce, 0);
            decryptedPayload=new byte[encryptedPayload.length];
            cipher.decrypt(decryptedPayload, encryptedPayload, encryptedPayload.length);
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

    /**
     * Now the payload has been decrypted, remove the inner header. Then
     * convert the rest to a database XML string
     * @return 
     */
    private boolean processDecryptedPayload()
    {
        boolean valid=true;
        
        if (header.getCompressionFlags()==0x01)
        {
            unzippedPayload=Toolbox.decompress(decryptedPayload);
        }
        else
        {
            unzippedPayload=decryptedPayload;
        }
        
        innerHeader=new DatabaseHeader(unzippedPayload, true);
        int length=innerHeader.getHeaderLength();
        xmlDatabase=new String(Toolbox.copyBytes(unzippedPayload, length, unzippedPayload.length-length), StandardCharsets.UTF_8);
        return valid;
    }
}
