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
        NO(0x00),
        ARC4(0x01),
        SALSA20(0x02);
        
        public final int value;

        private PasswordCipher(int value)
        {
            this.value=value;
        }

        public static PasswordCipher PasswordCipherOfValue(int value) 
        {
            for (PasswordCipher v : values()) 
            {
                if (v.value==value) 
                {
                    return v;
                }
            }
            return null;
        }
    }
    
    public enum ValueType
    {
        ENDOFHEADER             (0x00),
        CIPHERUUID              (0x02),
        COMPRESSIONFLAGS        (0x03),
        MASTERSEED              (0x04),
        KDFTRANSFORMSEED        (0x05),
        KDFTRANSFORMROUNDS      (0x06),
        ENCRYPTIONIV            (0x07),
        PASSWORDENCRYPTIONKEY   (0x08),
        STREAMSTARTBYTES        (0x09),
        RANDOMSTREAMID          (0x0A),
        KDFVARIANTLIBRARY       (0x0B);
        public final int value;

        private ValueType(int value)
        {
            this.value=value;
        }
    };

    private final byte[]        filedata;
    
    private HeaderFields        headerFields;
    // Header fields
    private byte[]              cipherUuid;
    private byte[]              masterSeed;
    private byte[]              encryptionIv;
    private Long                transformRounds;
    private byte[]              transformSeed;
    private byte[]              passwordEncryptionKey;
    private byte[]              streamStartBytes;
    private byte[]              endOfHeader;
    private byte[]              kdfParameters;
    private int                 signature1;
    private int                 signature2;
    private int                 kdbxMinorVersion;
    private int                 kdbxMajorVersion;
    private int                 lengthSize;
    private Long                compressionFlags;
    private PasswordCipher      passwordCipher;    
    
    private int                 headerLength;       // without hashes
    private int                 fullHeaderLength;   // with hashes
    private VariantDictionary   dictionary;
    
    private String              kdfUuid;            // $UUID
    private Long                kdfTransformRounds; // R
    private byte[]              kdfTransformSeed;   // S
    private Long                kdfIterations;      // I
    private Long                kdfMemorySize;      // M  in bytes
    private Integer             kdfParallelism;     // P
    private Integer             kdfV;               // V
         
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
            signature1          =(int)Toolbox.readInt(filedata, 0, 4);
            signature2          =(int)Toolbox.readInt(filedata, 4, 4);
            kdbxMinorVersion    =(int)Toolbox.readInt(filedata, 8, 2);
            kdbxMajorVersion    =(int)Toolbox.readInt(filedata,10, 2);

            if (kdbxMajorVersion==0x0003)
            {
                lengthSize=2;   // KDBX version 3.x
            }
            else if (kdbxMajorVersion==0x0004)
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
        
        headerFields=new HeaderFields(lengthSize, filedata, index);
        index+=headerFields.getFieldDataSize();
        processHeaderFields();
        if (isVersion4())
        {
            kdfParameters       =headerFields.getFieldData(ValueType.KDFVARIANTLIBRARY.value);
            processDictionary(kdfParameters);            
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
    
    private void processHeaderFields()
    {
        Long        integer;
        cipherUuid              =headerFields.getFieldData(ValueType.CIPHERUUID.value);
        masterSeed              =headerFields.getFieldData(ValueType.MASTERSEED.value);
        transformSeed           =headerFields.getFieldData(ValueType.KDFTRANSFORMSEED.value);
        kdfTransformSeed        =transformSeed;
        transformRounds         =headerFields.getFieldDataAsInteger(ValueType.KDFTRANSFORMROUNDS.value);
        kdfTransformRounds      =transformRounds;
        encryptionIv            =headerFields.getFieldData(ValueType.ENCRYPTIONIV.value);
        streamStartBytes        =headerFields.getFieldData(ValueType.STREAMSTARTBYTES.value);
        endOfHeader             =headerFields.getFieldData(ValueType.ENDOFHEADER.value);
        compressionFlags        =headerFields.getFieldDataAsInteger(ValueType.COMPRESSIONFLAGS.value);
        passwordEncryptionKey   =headerFields.getFieldData(ValueType.PASSWORDENCRYPTIONKEY.value);

        integer=headerFields.getFieldDataAsInteger(ValueType.RANDOMSTREAMID.value);
        if (integer!=null)
        {
            passwordCipher      =PasswordCipher.PasswordCipherOfValue(integer.intValue());
        }
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
        LOGGER.info("KDBX Version         : {}.{}", kdbxMajorVersion, kdbxMinorVersion);
        LOGGER.info("2 Cipher UUID        : {}", Toolbox.bytesToString(cipherUuid));
        LOGGER.info("3 Compression flags  : {}", compressionFlags);
        LOGGER.info("4 Master Seed        : {}", Toolbox.bytesToString(masterSeed));
        LOGGER.info("5 Transform Seed     : {}", Toolbox.bytesToString(transformSeed));
        LOGGER.info("6 Transform rounds   : {}", transformRounds);
        LOGGER.info("7 Encryption IV      : {}", Toolbox.bytesToString(encryptionIv));
        LOGGER.info("8 Password Encr. key : {}", Toolbox.bytesToString(passwordEncryptionKey));
        LOGGER.info("9 Stream start bytes : {}", Toolbox.bytesToString(streamStartBytes));
        LOGGER.info("A Random Stream ID   : {}", passwordCipher);
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
        return kdbxMajorVersion;
    }

    public int getLengthSize()
    {
        return lengthSize;
    }

    public Long getCompressionFlags()
    {
        return compressionFlags;
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
        return (kdbxMajorVersion==0x0003);
    }

    public boolean isVersion4()
    {
        return (kdbxMajorVersion==0x0004);
    }

    public String getKdfUuid()
    {
        return this.dictionary.getValueAsByteString("$UUID");
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
