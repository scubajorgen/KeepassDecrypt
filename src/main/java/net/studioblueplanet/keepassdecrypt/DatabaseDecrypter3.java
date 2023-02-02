/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author jorgen
 */
public class DatabaseDecrypter3 extends DatabaseDecrypterBase
{
    private final static Logger     LOGGER = LogManager.getLogger(DatabaseDecrypter3.class);
    private byte[]                  databaseBlocks;         // Database data containing the blocks
    private byte[]                  zippedDatabase;         // Blocks concatenated: gzip
    private byte[]                  unzippedDatabase;       // unzipped bytes of representing the database
    
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
        valid=generateMasterKey(password);
        if (valid)
        {
            valid=decryptPayload(filePayload);
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
     * Return the XML database as a string
     * @return The XML as string
     */
    public String getXmlDatabase()
    {
        return this.xmlDatabase;
    }

    /**
     * This method tries a password. It checks whether it results in
     * properly decrypted data. For version 3 the payload must be decrypted.
     * The 1st 32 decrypted bytes must correspond to the streamStartBytes
     * in the header
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
            valid=decryptPayload(filePayload);
            if (valid)
            {
                valid=validateDecryption();
            }
        }
        return valid;
    }  
    
    /**
     * Validate the decryption result by checking it with the unencrypted 
     * start bytes in the header (streamStartBytes). 
     * @return True if valid.
     */
    protected boolean validateDecryption()
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
     * The payload after decryption, prior to unzipping is subdivided in blocks.
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
        
        // calculate total payload size
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
        
        // Validate blocks and concatenate
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
