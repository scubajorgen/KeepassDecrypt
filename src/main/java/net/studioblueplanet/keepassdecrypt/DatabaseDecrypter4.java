/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

/**
 *
 * @author jorgen
 */
public class DatabaseDecrypter4 implements DatabaseDecrypter
{
    /**
     * Decrypt the database using the password given. 
     * @param password Password to use for decrypting
     * @return The Database XML as string
     */
    @Override
    public String decryptDatabase(String password)
    {
        return "";
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
}
