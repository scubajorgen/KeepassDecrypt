/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import net.studioblueplanet.keepassdecrypt.DatabaseHeader.PasswordCipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Keepass database decryption
 * @author jorgen
 */
public class KeepassDatabase
{
    private final static Logger LOGGER = LogManager.getLogger(KeepassDatabase.class);
    
    private DatabaseHeader      header;
    private DatabaseDecrypter   decrypter;

        
    // Intermediate and final process result
    private byte[]              filedata;               // raw file bytes
    private byte[]              encryptedDatabase;      // The part of the file containing the database data

    
    
            
    /**
     * Constructor. Reads and parses the information in the kdbx file
     * @param filename Filename of the kdbx file
     */
    public KeepassDatabase(String filename)
    {
        Path path = Paths.get(filename);
        
        try
        {
            filedata            = Files.readAllBytes(path);
            header              = new DatabaseHeader(filedata);
            encryptedDatabase   = Toolbox.copyBytes(filedata, header.getHeaderLength(), filedata.length-header.getHeaderLength());
            
            if (header.isVersion3())
            {
                decrypter=new DatabaseDecrypter3();
                decrypter.initialize(header, encryptedDatabase);            
            }
            else if (header.isVersion4())
            {
                decrypter=new DatabaseDecrypter4();
                decrypter.initialize(header, encryptedDatabase);            
            }
            else
            {
                LOGGER.error("Unsupporterd KDBX version");
            }
            LOGGER.info("Encrypted database length: {}", encryptedDatabase.length);            
        }
        catch (IOException e)
        {
            LOGGER.error("Error reading file {}: {}", filename, e.getMessage());
        }
    }
    
    /**
     * Decrypt the database using the password given. This method only 
     * applies to version 3.x KDBX databases.
     * @param password Password to use for decrypting
     * @return The Database XML as string
     */
    public String decryptDatabase(String password)
    {
        return decrypter.decryptDatabase(password);
    }
    
    /**
     * This method tries a password. It checks whether it results in
     * properly decrypted data
     * @param password Password to test
     * @return True if the password is valid, false if not
     */
    public boolean testPassword(String password)
    {
        return decrypter.testPassword(password);
    }
    
    /**
     * After proper decryption, this method returns the database as XML string
     * @return The XML string
     */
    public String getDatabaseAsXml()
    {
        return decrypter.getXmlDatabase();
    }
    
    /**
     * Returns the cipher used for inner password encryption
     * @return The cipher
     */
    public PasswordCipher getPasswordEncryption()
    {
        return header.getPasswordCipher();
    }
    
    /**
     * Get the password encryption/decryption key
     * @return Byte array
     */
    public byte[] getPasswordEncryptionKey()
    {
        return header.getPasswordEncryptionKey();
    }
    
    

    
    /**
     * Show the header info
     */
    public void dumpData()
    {
        header.dumpData();
    }
    
}
