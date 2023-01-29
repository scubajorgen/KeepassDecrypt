/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class decrypts KDBX v4 files
 * @author jorgen
 */
public class DatabaseDecrypter4 extends DatabaseDecrypterBase
{
    private final static Logger     LOGGER = LogManager.getLogger(DatabaseDecrypter4.class);

    private HeaderFields            innerHeader;
    private byte[]                  encryptedPayload;
    private byte[]                  unzippedPayload;
    private byte[]                  database;
    private byte[]                  pbHmacKey;
    private byte[]                  streamStartBytes;
    
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
                valid=decryptPayload(encryptedPayload);
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
        boolean valid;
        
        valid=generateMasterKey(password);
        if (valid)
        {
            valid=validateHeaderHmacHash();
        }
        return valid;
    }      
    
    /**
     * Validate the HMAC SHA256 hash of the header
     * @return 
     */
    private boolean validateHeaderHmacHash()
    {
        byte[] a            =Toolbox.concatenate(header.getMasterSeed(), transformedKey);
        byte[] b            ={1};
        byte[] c            =Toolbox.concatenate(a, b);
        pbHmacKey           =Toolbox.sha512(c);        

        byte[] headerHmacKey      =getHmacKey(0xffffffffffffffffL, pbHmacKey);
        
        boolean valid=header.validateHmacHash(headerHmacKey);
        
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
        while (index<filePayload.length)
        {
            index+=32;
            length=(int)Toolbox.readInt(filePayload, index, 4);
            totalLength+=length;
            index+=4;
            index+=length;
        }
        
        encryptedPayload=new byte[totalLength];
        i=0;
        index=0;
        totalLength=0;
        valid=true;
        while (index<filePayload.length && valid)
        {
            hash=Toolbox.copyBytes(filePayload, index, 32);
            index+=32;
            
            length=(int)Toolbox.readInt(filePayload, index, 4);
            index+=4;
            System.arraycopy(filePayload, index, encryptedPayload, totalLength, length);
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
        
        innerHeader =new HeaderFields(4, unzippedPayload, 0);
        int length  =innerHeader.getFieldDataSize();
        xmlDatabase =new String(Toolbox.copyBytes(unzippedPayload, length, unzippedPayload.length-length), StandardCharsets.UTF_8);
        return valid;
    }
}
