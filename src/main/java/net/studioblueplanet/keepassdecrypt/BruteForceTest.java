/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class that executes a brute force test on the Keepass database in order to 
 * find the password. It is not very efficient since it only uses one thread,
 * a limited set of characters and Java.
 * @author jorgen
 */
public class BruteForceTest
{
    private final static Logger     LOGGER = LogManager.getLogger(BruteForceTest.class);
    
    private String                  passwordChars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890";
    private final KeepassDatabase   database;
    
    /**
     * Constructor, pass the name of de Keepass file
     * @param filename 
     */
    public BruteForceTest(String filename)
    {
        database=new KeepassDatabase(filename);
    }
    
    
    /**
     * Execute the brute force test
     * @param maxChars Maximum number of characters you want to test.
     * @return True if password found, false if not
     */
    public boolean execute(int maxChars)
    {
        boolean found=false;
        
        for (int numberOfChars=1; numberOfChars<=maxChars && !found; numberOfChars++)
        {
            long start = System.currentTimeMillis();
            found=attack("", numberOfChars);
            long end = System.currentTimeMillis();
            long elapsedTime = (end - start);
            if (!found)
            {
                LOGGER.info("Parsing all passwords of {} chars took {} milliseconds", numberOfChars, elapsedTime);
            }
        }
        return found;
    }
    
    /**
     * Set the series of allowed characters as a string, like "abcdefgABCDEFG0123#$"
     */
    public void setPasswordChars(String passwordChars)
    {
        this.passwordChars=passwordChars;
    }
    
    /**
     * Brute force method that recursively tries all passwords of given length.
     * @param prefix First part of the password, recursively add the rest.
     * @param chars Length of the passwords 
     */
    private boolean attack(String prefix, int chars)
    {
        String password;
        boolean found;
        
        found=false;
        for(int i=0;i<passwordChars.length() && !found;i++)
        {
            password=prefix+passwordChars.charAt(i);
            if (chars==1)
            {
                LOGGER.info("Testing {}", password);
                if (database.testPassword(password))
                {
                    LOGGER.info("Password found: {}", password);
                    found=true;
                }
            }
            else
            {
                found=attack(password, chars-1);
            }
        }
        return found;
    }
}
