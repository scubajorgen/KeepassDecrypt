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
public class DatabaseHeader
{
    private final static Logger LOGGER = LogManager.getLogger(DatabaseHeader.class);
    
    public enum PasswordCipher
    {
        NO,
        ARC4,
        SALSA20       
    }

    private byte[]              filedata;
    // Header fields
    private byte[]              cipherUuid;
    private byte[]              masterSeed;
    private byte[]              transformSeed;
    private byte[]              encryptionIv;
    private byte[]              passwordEncryptionKey;
    private byte[]              streamStartBytes;
    private byte[]              endOfHeader;
    private byte[]              kdfParameters;
    private int                 signature1;
    private int                 signature2;
    private int                 kdbxVersion;
    private int                 lengthSize;
    private int                 compressionFlags;
    private long                transformRounds;
    private int                 randomStreamId;
    private PasswordCipher      passwordCipher;    
    
    private int                 headerLength;
    
    /**
     * Constuctor. Parses the header data
     * @param headerData Header data
     */
    public DatabaseHeader(byte[] headerData)
    {
        this.filedata=headerData;
        parseData();
    }

    /**
     * Processes the file data into sensible things
     */
    private void parseData()
    {
        int     index;
        byte    type;
        int     length;
        
        
        LOGGER.info("Parsing data");
        signature1  =(int)Toolbox.readInt(filedata, 0, 4);
        signature2  =(int)Toolbox.readInt(filedata, 4, 4);
        kdbxVersion =(int)Toolbox.readInt(filedata, 8, 4);

        if (kdbxVersion==0x00030001)
        {
            lengthSize=2;   // KDBX version 3.x
        }
        else if (kdbxVersion==0x00040000)
        {
            lengthSize=4;   // KDBX version 4.x
        }
        
        index   =12;
        type    =-1;
        while (type!=0x00)
        {
            type    =filedata[index];
            length  =(int)Toolbox.readInt(filedata, index+1, lengthSize);
            switch(type)
            {
                default:
                    LOGGER.error("Unknown header field {}", type);
                    break;
                case 0x00:
                    endOfHeader             =Toolbox.copyBytes(filedata, index+3, length);
                    break;
                case 0x01:
                    break;
                case 0x02:
                    cipherUuid              =Toolbox.copyBytes(filedata, index+3, length);
                    break;
                case 0x03:
                    compressionFlags        =(int)Toolbox.readInt(filedata, index+3, length);
                    break;
                case 0x04:
                    masterSeed              =Toolbox.copyBytes(filedata, index+3, length);
                    break;
                case 0x05:
                    transformSeed           =Toolbox.copyBytes(filedata, index+3, length);
                    break;
                case 0x06:
                    transformRounds         =Toolbox.readInt(filedata, index+3, length);
                    break;
                case 0x07:
                    encryptionIv            =Toolbox.copyBytes(filedata, index+3, length);
                    break;
                case 0x08:
                    passwordEncryptionKey   =Toolbox.copyBytes(filedata, index+3, length);
                    break;
                case 0x09:
                    streamStartBytes        =Toolbox.copyBytes(filedata, index+3, length);
                    break;
                case 0x0a:
                    randomStreamId          =(int)Toolbox.readInt(filedata, index+3, length);
                    switch(randomStreamId)
                    {
                        case 1:
                            passwordCipher=PasswordCipher.ARC4;
                            break;
                        case 2:
                            passwordCipher=PasswordCipher.SALSA20;
                            break;
                        case 0:
                        default:
                            passwordCipher=PasswordCipher.NO;
                            break;
                    }
                    break;
                case 0x0b:
                    kdfParameters     =Toolbox.copyBytes(filedata, index+3, length);
                    break;
            }
            index+=length+lengthSize+1;

        }
        
        // The number of bytes read for the header
        headerLength=index;
    }

    /**
     * Show the header info
     */
    public void dumpData()
    {
        LOGGER.info("Header Signature 1   : {}", String.format("%x", signature1));
        LOGGER.info("Header Signature 2   : {}", String.format("%x", signature2));
        LOGGER.info("KDBX Version         : {}", String.format("%x", kdbxVersion));
        LOGGER.info("2 Cipher UUID        : {}", Toolbox.bytesToString(cipherUuid));
        LOGGER.info("3 Compression flags  : {}", compressionFlags);
        LOGGER.info("4 Master Seed        : {}", Toolbox.bytesToString(masterSeed));
        LOGGER.info("5 Transform Seed     : {}", Toolbox.bytesToString(transformSeed));
        LOGGER.info("6 Transform rounds   : {}", transformRounds);
        LOGGER.info("7 Encryption IV      : {}", Toolbox.bytesToString(encryptionIv));
        LOGGER.info("8 Password Encr. key : {}", Toolbox.bytesToString(passwordEncryptionKey));
        LOGGER.info("9 Stream start bytes : {}", Toolbox.bytesToString(streamStartBytes));
        LOGGER.info("A Random Stream ID   : {}", randomStreamId);
        LOGGER.info("B KDF parameters     : {}", Toolbox.bytesToString(kdfParameters));
        LOGGER.info("0 End of header      : {}", Toolbox.bytesToString(endOfHeader));
    }    
    
    public static Logger getLOGGER()
    {
        return LOGGER;
    }

    public byte[] getCipherUuid()
    {
        return cipherUuid;
    }

    public byte[] getMasterSeed()
    {
        return masterSeed;
    }

    public byte[] getTransformSeed()
    {
        return transformSeed;
    }

    public byte[] getEncryptionIv()
    {
        return encryptionIv;
    }

    public byte[] getPasswordEncryptionKey()
    {
        return passwordEncryptionKey;
    }

    public byte[] getStreamStartBytes()
    {
        return streamStartBytes;
    }

    public byte[] getEndOfHeader()
    {
        return endOfHeader;
    }

    public byte[] getKdfParameters()
    {
        return kdfParameters;
    }

    public int getSignature1()
    {
        return signature1;
    }

    public int getSignature2()
    {
        return signature2;
    }

    public int getKdbxVersion()
    {
        return kdbxVersion;
    }

    public int getLengthSize()
    {
        return lengthSize;
    }

    public int getCompressionFlags()
    {
        return compressionFlags;
    }

    public long getTransformRounds()
    {
        return transformRounds;
    }

    public int getRandomStreamId()
    {
        return randomStreamId;
    }

    public PasswordCipher getPasswordCipher()
    {
        return passwordCipher;
    }

    public int getHeaderLength()
    {
        return headerLength;
    }

    public boolean isVersion3()
    {
        return ((kdbxVersion&0x00FF0000)==0x00030000);
    }

    public boolean isVersion4()
    {
        return ((kdbxVersion&0x00FF0000)==0x00040000);
    }

}
