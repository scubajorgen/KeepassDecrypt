/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author jorgen
 */
public class VariantDictionary
{
    public enum ValueType
    {
        UINT32(0x04),
        UINT64(0x05),
        BOOL(0x08),
        INT32(0x0C),
        INT64(0x0D),
        STRING(0x18),
        BYTEARRAY(0x42);
        public final int value;

        private ValueType(int value)
        {
            this.value=value;
        }

        public static ValueType ValueTypeOfValue(int value) 
        {
            for (ValueType v : values()) 
            {
                if (v.value==value) 
                {
                    return v;
                }
            }
            return null;
        }
    };
    
    /**
     * Class that represents a Variant
     */
    public class Variant
    {
    
        private final ValueType        type;
        private final String           name;
        private final byte[]           value;
        
        /**
         * Constructor, creates the Variant
         * @param type Type of the value
         * @param name Name of the entry
         * @param value Value of the entry
         */
        public Variant(ValueType type, String name, byte[] value)
        {
            this.type=type;
            this.name=name;
            this.value=value;
        }
        public ValueType getValueType()
        {
            return type;
        }
        
        public String getName()
        {
            return name;
        }
        
        public Integer getValueAsInt()
        {
            Integer theInt=null;
            if (type==ValueType.INT32 || type==ValueType.UINT32)
            {
                theInt=(int)Toolbox.readInt(value, 0, 4);
            }
            else
            {
                LOGGER.error("Illegal value request");
            }
            return theInt;
        }
        
        public Long getValueAsLong()
        {
            Long theLong=null;
            if (type==ValueType.INT64 || type==ValueType.UINT64)
            {
                theLong=Toolbox.readInt(value, 0, 8);
            }
            else
            {
                LOGGER.error("Illegal value request");
            }
            return theLong;
        }
        
        public byte[] getValueAsByteArray()
        {
            if (type!=ValueType.BYTEARRAY)
            {
                LOGGER.error("Illegal value request");
            }
            return value;
        }
                
        public String getValueAsString()
        {
            if (type!=ValueType.STRING)
            {
                LOGGER.error("Illegal value request");
            }
            return new String(value);
        }

        public String getValueAsByteString()
        {
            if (type!=ValueType.STRING)
            {
                LOGGER.error("Illegal value request");
            }
            return Toolbox.bytesToString(value);
        }

    }
    private final static Logger             LOGGER = LogManager.getLogger(VariantDictionary.class);
 
    private final int                       version;
    private final HashMap<String, Variant>  variants;          
    

    
    public VariantDictionary(byte[] dictionaryData)
    {
        int         type;
        ValueType   valueType;
        String      name;
        byte[]      value;
        int         nameLength;
        int         valueLength;
        
        int         index;
        
        variants=new HashMap<>();
        index   =0;
        version =(int)Toolbox.readInt(dictionaryData, index, 2);
        index+=2;
        
        type    =-1;
        while (type!=0)
        {
            type=dictionaryData[index++];
            if (type!=0 && index<dictionaryData.length)
            {
                valueType=ValueType.ValueTypeOfValue(type);
                nameLength=(int)Toolbox.readInt(dictionaryData, index, 4);
                index+=4;
                name=new String(Toolbox.copyBytes(dictionaryData, index, nameLength));
                index+=nameLength;
                valueLength=(int)Toolbox.readInt(dictionaryData, index, 4);
                index+=4;
                value=Toolbox.copyBytes(dictionaryData, index, valueLength);
                index+=valueLength;
                Variant v=new Variant(valueType, name, value);
                LOGGER.info("Type {}, name {}, value {}", v.type, v.name, Toolbox.bytesToString(v.value));
                variants.put(name, v);
            }
        }
        LOGGER.info("Done");
    }
    
    public void dumpDictionary()
    {
        for (String key:variants.keySet())
        {
            Variant v=variants.get(key);
            switch (v.type)
            {
                case INT32:
                case UINT32:
                    LOGGER.info("Name {} Value {}", v.name, v.getValueAsInt());
                    break;
                case INT64:
                case UINT64:
                    LOGGER.info("Name {} Value {}", v.name, v.getValueAsLong());
                    break;
                case STRING:
                    LOGGER.info("Name {} Value {}", v.name, new String(v.value));
                    break;
                case BYTEARRAY:
                    LOGGER.info("Name {} Value {}", v.name, Toolbox.bytesToString(v.value));
                    break;
            }
        }
    }
    
    /**
     * Return value by name as byte array
     * @param name Name of the dictionary entry
     * @return The value or null if not found
     */
    public byte[] getValueAsByteArray(String name)
    {
        return variants.get(name).getValueAsByteArray();
    }
    
    /**
     * Return value by name as String
     * @param name Name of the dictionary entry
     * @return The value or null if not found
     */
    public String getValueAsString(String name)
    {
        return variants.get(name).getValueAsString();
    }
    
    /**
     * Return value by name as Stringified bytes
     * @param name Name of the dictionary entry
     * @return The value or null if not found
     */
    public String getValueAsByteString(String name)
    {
        return variants.get(name).getValueAsByteString();
    }
    
    /**
     * Return value by name as Long
     * @param name Name of the dictionary entry
     * @return The value or null if not found
     */
    public Long getValueAsLong(String name)
    {
        return variants.get(name).getValueAsLong();
    }
    
    /**
     * Return value by name as Long
     * @param name Name of the dictionary entry
     * @return The value or null if not found
     */
    public Integer getValueAsInt(String name)
    {
        return variants.get(name).getValueAsInt();
    }
    
}
