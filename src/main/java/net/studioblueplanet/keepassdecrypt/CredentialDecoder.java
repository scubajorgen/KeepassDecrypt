/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.w3c.dom.*;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.xml.parsers.*;
import net.studioblueplanet.keepassdecrypt.KeepassDatabase.PasswordCipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.rzo.netty.ahessian.crypto.CryptoException;
import org.rzo.netty.ahessian.crypto.StreamCipher;
import org.rzo.netty.ahessian.crypto.StreamCipherFactory;


/**
 * Represents a set of credentials as present in the Keepass database.
 * It just parses each credential, omitting the groups and details
 * @author jorgen
 */
public class CredentialDecoder
{
    public class Credential
    {
        public String title;
        public String username;
        public String password;
    }
    private final static Logger LOGGER  = LogManager.getLogger(CredentialDecoder.class);
    
    private static final byte[] IV      ={(byte)0xE8, (byte)0x30, (byte)0x09, (byte)0x4B, 
                                          (byte)0x97, (byte)0x20, (byte)0x5D, (byte)0x2A};

    private StreamCipher        cipher;
    
    private List<Credential>    credentials;
                
    
    /**
     * Credentials extracting.
     * @param xml The Keepass database as XML string
     * @param passwordCipher Password Cipher to use
     * @param passwordKey  Password decoding key to use
     */
    public CredentialDecoder(String xml, PasswordCipher passwordCipher, byte[] passwordKey)
    {
        initDecryption(passwordCipher, passwordKey);
        credentials = new ArrayList<>();
        try
        {
            DocumentBuilderFactory factory =
            DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder(); 
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            Element root = doc.getDocumentElement();
            NodeList entries=root.getElementsByTagName("Entry");
            for (int i=0;i<entries.getLength();i++)
            {
                Credential credential=new Credential();
                Node node=entries.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE)
                {
                    Element entry=(Element)node;
                    
                    NodeList strings=entry.getElementsByTagName("String");
                    for (int j=0;j<strings.getLength();j++)
                    {
                        Node stringNode=strings.item(j);
                        if (stringNode.getNodeType() == Node.ELEMENT_NODE)
                        {
                            Element string=(Element)stringNode;
                            String key  =((Element)(string.getElementsByTagName("Key").item(0))).getTextContent();
                            String value=((Element)(string.getElementsByTagName("Value").item(0))).getTextContent();
                            LOGGER.debug("Key {} Value {}", key, value);
                            if ("Title".equals(key))
                            {
                                credential.title=value;
                                LOGGER.info("Title: {}", credential.title);
                            }
                            if ("UserName".equals(key))
                            {
                                credential.username=value;
                                LOGGER.info("Username: {}", credential.username);
                            }
                            if ("Password".equals(key))
                            {
                                String passwordString=value;
                                
                                NamedNodeMap attributes=string.getElementsByTagName("Value").item(0).getAttributes();
                                String prot=attributes.getNamedItem("Protected").getNodeValue();
                                
                                String decryptedPassword=null;
                                if ("True".equals(prot))
                                {
                                    credential.password=decryptPassword(passwordString);
                                }
                                else
                                {
                                    // UNSURE OF THIS!!!
                                    credential.password=passwordString;
                                }
                                LOGGER.info("Password: {}", credential.password);
                            }
                        
                        }
                    }
                }
                credentials.add(credential);
            }
            
        }
        catch (ParserConfigurationException e)
        {
            LOGGER.error("Configuration error parsing XML: {}", e.getMessage());
        }
        catch (SAXException e)
        {
            LOGGER.error("SAX Error parsing XML: {}", e.getMessage());
        }
        catch (IOException e)
        {
            LOGGER.error("I/O Error parsing XML: {}", e.getMessage());
        }
    }
    
    /**
     * Return the list of credentials
     * @return The list.
     */
    public List<Credential> getCredentials()
    {
        return credentials;
    }
    
    /**
     * Initializes the decryption engine
     * @param passwordCipher Decryption to use
     * @param passwordKey Key to use
     */
    private void initDecryption(PasswordCipher passwordCipher, byte[] passwordKey)
    {
        byte[] compositeKey=new byte[32];
        
        
        if (passwordCipher==PasswordCipher.SALSA20)
        {
            cipher = StreamCipherFactory.createCipher("Salsa20");
        }
        else if (passwordCipher==PasswordCipher.ARC4)
        {
            cipher = StreamCipherFactory.createCipher("RC4");
        }
        
        // SHA256(key)
        try
        {
            MessageDigest digest    =MessageDigest.getInstance("SHA-256");
            compositeKey            =digest.digest(passwordKey);
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.error("Error calculating SHA256 of key: {}", e.getMessage());
        }   

        // Decryption engine init; must be done once
        try
        {
            cipher.engineInitDecrypt(compositeKey, IV);
        }
        catch (CryptoException e)
        {
            LOGGER.error("Error initializing password decryption {}", e.getMessage());
        }        
    }
    
    
    /**
     * This method decrypts the password
     * @param passwordBase64 Base64 encoded encrypted password
     * @return Decrypted password
     */
    private String decryptPassword(String passwordBase64)
    {
        String password     ="";
       
        byte[] decodedBytes = Base64.getDecoder().decode(passwordBase64.getBytes(StandardCharsets.US_ASCII));
        try
        {
            byte[] decrypted=cipher.crypt(decodedBytes, 0, decodedBytes.length);
            password=new String(decrypted, StandardCharsets.US_ASCII);
        }
        catch (CryptoException e)
        {
            LOGGER.error("Error decrypting password {}", e.getMessage());
        }
        return password;
    }
}
