/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 *
 * @author jorgen
 */
public class HeaderFields
{
    public class HeaderFieldData
    {
        public HeaderFieldData(byte[] data, int size)
        {
            this.data=data;
            this.size=size;
        }
        public byte[]  data;
        public int     size;
    }
    
    private final static Logger                 LOGGER      = LogManager.getLogger(HeaderFields.class);


    private final int                           lengthSize;
    private final byte[]                        fieldData;
    private final int                           startIndex;
    private int                                 processedBytes;
    
    private final HashMap<Integer, HeaderFieldData>  fields;
    
    /**
     * Constructor. Parses the file data for header fields
     * @param fieldLength Size of the length attribute (kdbx3: 2, kdbx4: 4)
     * @param fileData Raw data
     * @param startIndex Start index in the raw data
     */
    public HeaderFields(int fieldLength, byte[] fileData, int startIndex)
    {
        this.lengthSize =fieldLength;
        this.fieldData  =fileData;
        this.startIndex =startIndex;
        fields          =new HashMap<>();
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
        
        index   =startIndex;
        type    =-1;
        while (type!=0x00)
        {
            type    =fieldData[index++];
            length  =(int)Toolbox.readInt(fieldData, index, lengthSize);
            index+=lengthSize;
            byte[] field=Toolbox.copyBytes(fieldData, index, length);
            index+=length;
            HeaderFieldData headerData=new HeaderFieldData(field, length);
            fields.put((int)type, headerData);
        }
        processedBytes=index-startIndex;
    }

    /**
     * Returns the total size of the header fields
     * @return Size of the header fields aka number of processed bytes
     */
    public int getFieldDataSize()
    {
        return processedBytes;
    }
    
    /**
     * Get a field
     * @param fieldId ID Of the field
     * @return The content or null if non existent
     */
    public byte[] getFieldData(int fieldId)
    {
        byte[] data;
        HeaderFieldData field=fields.get(fieldId);
        if (field!=null)
        {
            data=field.data;
        }
        else
        {
            data=null;
        }
        return data;
    }
    
    /**
     * Get a field as string of hex values
     * @param fieldId ID Of the field
     * @return The content or null if non existent
     */
    public String getFieldDataAsByteString(int fieldId)
    {
        byte[]  theBytes=getFieldData(fieldId);
        String  theString;
        
        if (theBytes!=null)
        {
            theString=Toolbox.bytesToString(theBytes);
        }
        else
        {
            theString=null;
        }
        
        return theString;
    }
    
    /**
     * Get a field as string of hex values
     * @param fieldId ID Of the field
     * @return The content or null if non existent
     */
    public Long getFieldDataAsInteger(int fieldId)
    {
        Long    theInt;
        
        HeaderFieldData field=fields.get(fieldId);
        if (field!=null)
        {
            byte[]  theBytes=field.data;
            int     size    =field.size;
            theInt=Toolbox.readInt(theBytes, 0, size);
        }
        else
        {
            theInt=null;
        }        
        return theInt;
    }    
}
