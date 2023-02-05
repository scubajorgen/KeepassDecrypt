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
  
    /**
     * The cipher used for the inner passwords
     */
    public static enum PasswordCipher
    {
        NO(0x00),
        ARC4(0x01),
        SALSA20(0x02),
        CHACHA20(0x03);
        
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
    
    public static enum Cipher
    {
        UNKNOWN(""),
        AESCBC("31c1f2e6bf714350be5805216afc5aff"),
        TWOFISH("not supported"),
        CHACHA20("d6038a2b8b6f4cb5a524339a31dbb59a"),
        AESECB("c9d9f39a628a4460bf740d08c18a4fea"),
        ARGON2D("ef636ddf8c29444b91f7a9a403e30a0c"),
        ARGON2ID("9e298b1956db4773b23dfc3ec6f0a1e6");
        
        public final String value;

        private Cipher(String value)
        {
            this.value=value;
        }

        public static Cipher CipherFromUuid(String value) 
        {
            for (Cipher v : values()) 
            {
                if (v.value.equals(value.toLowerCase())) 
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

    public enum InnerHeaderValueType
    {
        ENDOFHEADER             (0x00),
        RANDOMSTREAMID          (0x01),
        PASSWORDENCRYPTIONKEY   (0x02),
        BINARY                  (0x03);
        public final int value;

        private InnerHeaderValueType(int value)
        {
            this.value=value;
        }
    };
    
    
    private final byte[]        filedata;
    
    private HeaderFields        headerFields;
    // Header fields
    private String              cipherUuid;
    private Cipher              payloadCipher;
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
    private Cipher              kdfCipher;          // The $UUID as cipher
    private Long                kdfTransformRounds; // R
    private byte[]              kdfTransformSeed;   // S
    private Long                kdfIterations;      // I
    private Long                kdfMemorySize;      // M  in bytes
    private Integer             kdfParallelism;     // P
    private Integer             kdfVersion;         // V
    private byte[]              kdfTransformKey;    // K
                                                    // A
         
    private byte[]              headerHash;
    private byte[]              hmacHeaderHash;
    
    /**
     * Constuctor. Parses the header data
     * @param headerData Header data
     */
    public DatabaseHeader(byte[] headerData)
    {
        kdfCipher=Cipher.AESECB; // Default value for KDBX 3.x
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
        byte[] cipherUuidBytes  =headerFields.getFieldData(ValueType.CIPHERUUID.value);
        if (cipherUuidBytes!=null)
        {
            cipherUuid   =Toolbox.bytesToString(cipherUuidBytes);
            payloadCipher=Cipher.CipherFromUuid(cipherUuid);
        }
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
     * Process the inner header in case of KDBX 4. The Inner header is the first
     * part of the encryted content.
     * @param innerHeader The decoded inner header
     */
    public void processInnerHeaderFields(HeaderFields innerHeader)
    {
        passwordEncryptionKey   =innerHeader.getFieldData(InnerHeaderValueType.PASSWORDENCRYPTIONKEY.value);
        Long integer=innerHeader.getFieldDataAsInteger(InnerHeaderValueType.RANDOMSTREAMID.value);
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
        LOGGER.info("2 Cipher UUID        : {} ({})", cipherUuid, payloadCipher);
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
            LOGGER.info("KDF cipher UUID      : {} - ({})", kdfUuid, kdfCipher);
            LOGGER.info("KDF Transform rounds : {}", kdfTransformRounds);
            LOGGER.info("KDF Transform seed   : {}", Toolbox.bytesToString(kdfTransformSeed));
            LOGGER.info("KDF Iterations       : {}", kdfIterations);
            LOGGER.info("KDF Parallelism      : {}", kdfParallelism);
            LOGGER.info("KDF mem size         : {}", kdfMemorySize);
            LOGGER.info("KDF Version          : {}", String.format("0x%x", kdfVersion));
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
        
        if (kdfUuid!=null)
        {
            kdfCipher=Cipher.CipherFromUuid(kdfUuid);
            if (kdfCipher==Cipher.AESECB)
            {
                kdfTransformRounds      =dictionary.getValueAsLong("R");
                kdfTransformSeed        =dictionary.getValueAsByteArray("S");
            }
            else if (kdfCipher==Cipher.ARGON2D  || kdfCipher==Cipher.ARGON2ID)
            {
                kdfIterations           =dictionary.getValueAsLong("I");
                kdfMemorySize           =dictionary.getValueAsLong("M");
                kdfParallelism          =dictionary.getValueAsInt("P");
                kdfVersion              =dictionary.getValueAsInt("V");
                kdfTransformSeed        =dictionary.getValueAsByteArray("S");
            }
        }
    }


    public String getCipherUuid()
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

    public int getKdfVersion()
    {
        return kdfVersion;
    }

    public byte[] getHmacHeaderHash()
    {
        return hmacHeaderHash;
    }

    public byte[] getFiledata()
    {
        return filedata;
    }

    public Cipher getPayloadCipher()
    {
        return payloadCipher;
    }

    public Cipher getKdfCipher()
    {
        return kdfCipher;
    }

}
