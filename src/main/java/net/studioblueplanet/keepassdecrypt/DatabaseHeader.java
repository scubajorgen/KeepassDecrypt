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
    private final static Logger LOGGER      = LogManager.getLogger(DatabaseHeader.class);
    
    public static final String UUID_AESCBC     ="31c1f2e6bf714350be5805216afc5aff";
    public static final String UUID_TWOFISH    ="";
    public static final String UUID_CHACHA20   ="d6038a2b8b6f4cb5a524339a31dbb59a";

    public static final String UUID_AESECB     ="c9d9f39a628a4460bf740d08c18a4fea";
    public static final String UUID_ARGON2D    ="ef636ddf8c29444b91f7a9a403e30a0c";
    public static final String UUID_ARGON2ID   ="9e298b1956db4773b23dfc3ec6f0a1e6";
    
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
    
    private int                 headerLength;       // without hashes
    private int                 fullHeaderLength;   // with hashes
    private VariantDictionary   dictionary;
    
    private String              kdfUuid;            // $UUID
    private long                kdfTransformRounds; // R
    private byte[]              kdfTransformSeed;   // S
    private long                kdfIterations;      // I
    private long                kdfMemorySize;      // M  in bytes
    private int                 kdfParallelism;     // P
    private int                 kdfV;               // V
         
    private byte[]              headerHash;
    private byte[]              hmacHeaderHash;
    
    
    
    /**
     * Constuctor. Parses the header data
     * @param headerData Header data
     */
    public DatabaseHeader(byte[] headerData)
    {
        this.filedata=headerData;
        parseData(false);
    }

    /**
     * Constuctor. Parses the header data
     * @param headerData Header data
     * @param processOnlyFields True if the header only consists of fields and
     *                          does not have a signature or version
     */
    public DatabaseHeader(byte[] headerData, boolean processOnlyFields)
    {
        this.filedata=headerData;
        parseData(processOnlyFields);
    }

    /**
     * Processes the file data into sensible things
     */
    private void parseData(boolean processOnlyFields)
    {
        int     index;
        byte    type;
        int     length;
        
        
        LOGGER.info("Parsing data");
        if (!processOnlyFields)
        {
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
        }
        else
        {
            index=0;
            lengthSize=4;
        }
        
        
        type    =-1;
        while (type!=0x00)
        {
            type    =filedata[index++];
            length  =(int)Toolbox.readInt(filedata, index, lengthSize);
            index+=lengthSize;
            switch(type)
            {
                default:
                    LOGGER.error("Unknown header field {}", type);
                    break;
                case 0x00:
                    endOfHeader             =Toolbox.copyBytes(filedata, index, length);
                    break;
                case 0x01:
                    break;
                case 0x02:
                    cipherUuid              =Toolbox.copyBytes(filedata, index, length);
                    break;
                case 0x03:
                    compressionFlags        =(int)Toolbox.readInt(filedata, index, length);
                    break;
                case 0x04:
                    masterSeed              =Toolbox.copyBytes(filedata, index, length);
                    break;
                case 0x05:
                    transformSeed           =Toolbox.copyBytes(filedata, index, length);
                    break;
                case 0x06:
                    transformRounds         =Toolbox.readInt(filedata, index, length);
                    break;
                case 0x07:
                    encryptionIv            =Toolbox.copyBytes(filedata, index, length);
                    break;
                case 0x08:
                    passwordEncryptionKey   =Toolbox.copyBytes(filedata, index, length);
                    break;
                case 0x09:
                    streamStartBytes        =Toolbox.copyBytes(filedata, index, length);
                    break;
                case 0x0a:
                    randomStreamId          =(int)Toolbox.readInt(filedata, index, length);
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
                    kdfParameters       =Toolbox.copyBytes(filedata, index, length);
                    processDictionary(kdfParameters);
                    break;
            }
            index+=length;

        }
        
        headerLength=index;
        // The number of bytes read for the header
        if (!processOnlyFields && isVersion4())
        {
            headerHash      =Toolbox.copyBytes(filedata, index, 32);
            index+=32;
            hmacHeaderHash  =Toolbox.copyBytes(filedata, index, 32);
            index+=32;
            
            byte[] header   =Toolbox.copyBytes(filedata, 0, headerLength);
            byte[] hash     =Toolbox.sha256(header);
            if (!Toolbox.validateSha256Hash(header, hash))
            {
                LOGGER.error("Header error: hash does not match!");
            }
        }
        fullHeaderLength=index;
    }
    
    /**
     * Validates the hmac sha256 hash of the header, given the key
     * @param hmacKey The key to use for the HMAC SHA256
     * @return True if valid, false if not.
     */
    public boolean validateHmacHash(byte[] hmacKey)
    {
        byte[] headerBytes  =Toolbox.copyBytes(filedata, 0, headerLength);
        boolean valid=Toolbox.validateHmacSha256Hash(headerBytes, hmacKey, this.hmacHeaderHash);
        return valid;
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
        if (dictionary!=null)
        {
            LOGGER.info("KDF PARAMETERS (VERSION 4)");
            LOGGER.info("KDF cipher UUID      : {}", kdfUuid);
            LOGGER.info("KDF Transform rounds : {}", kdfTransformRounds);
            LOGGER.info("KDF Transform seed   : {}", Toolbox.bytesToString(kdfTransformSeed));
            LOGGER.info("KDF Iterations       : {}", kdfIterations);
            LOGGER.info("KDF Parallelism      : {}", kdfParallelism);
            LOGGER.info("KDF mem size         : {}", kdfMemorySize);
            LOGGER.info("KDF V                : {}", kdfV);
        }
    }    
    
    /**
     * Process the bytes into a VariantDictornary
     * @param kdfParameters The bytes to process
     */
    private void processDictionary(byte[] kdfParameters)
    {
        dictionary  =new VariantDictionary(kdfParameters);     
        kdfUuid     =dictionary.getValueAsByteString("$UUID");
        
        if (UUID_AESECB.equals(kdfUuid))
        {
            kdfTransformRounds      =dictionary.getValueAsLong("R");
            kdfTransformSeed        =dictionary.getValueAsByteArray("S");
        }
        else if (UUID_ARGON2D.equals(kdfUuid)  || UUID_ARGON2ID.equals(kdfUuid))
        {
            kdfIterations           =dictionary.getValueAsLong("I");
            kdfMemorySize           =dictionary.getValueAsLong("M");
            kdfParallelism          =dictionary.getValueAsInt("P");
            kdfV                    =dictionary.getValueAsInt("V");
            kdfTransformSeed        =dictionary.getValueAsByteArray("S");
        }
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
        return fullHeaderLength;
    }

    public boolean isVersion3()
    {
        return ((kdbxVersion&0x00FF0000)==0x00030000);
    }

    public boolean isVersion4()
    {
        return ((kdbxVersion&0x00FF0000)==0x00040000);
    }

    public String getKdfUuid()
    {
        return kdfUuid;
    }

    public long getKdfTransformRounds()
    {
        return kdfTransformRounds;
    }

    public byte[] getKdfTransformSeed()
    {
        return kdfTransformSeed;
    }

    public long getKdfIterations()
    {
        return kdfIterations;
    }

    public long getKdfMemorySize()
    {
        return kdfMemorySize;
    }

    public int getKdfParallelism()
    {
        return kdfParallelism;
    }

    public int getKdfV()
    {
        return kdfV;
    }

    public byte[] getHmacHeaderHash()
    {
        return hmacHeaderHash;
    }

    public byte[] getFiledata()
    {
        return filedata;
    }
    
}
