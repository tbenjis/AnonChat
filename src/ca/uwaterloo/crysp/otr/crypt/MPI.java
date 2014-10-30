/*
 *  Java OTR library
 *  Copyright (C) 2008-2009  Ian Goldberg, Muhaimeen Ashraf, Andrew Chung,
 *                           Can Tang
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package ca.uwaterloo.crysp.otr.crypt;

import ca.uwaterloo.crysp.otr.Data;
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.OutBuf;

public class MPI extends Data
{
    /** Constructor
     * @param value the value of data
     */
    public MPI(byte[] value)
    {
        super(value);
    }
    

    /** Read and return a MPI value from the InBuf stream
     * @param stream input buffer stream
     * @return MPI object
     */
    public static MPI readMPI(InBuf stream) throws OTRException
    {
        int length = (int)stream.readUInt();
        if(length == 0) {
            return new MPI(null);
        }

        byte[] value = stream.readBytes(length);

        // skip leading 0x00 bytes
        int srcPosition = 0;
        for(; srcPosition < value.length && value[srcPosition] == (byte)0x00; srcPosition++) {
        }

        if(srcPosition == 0) {
            return new MPI(value);
        } else if(srcPosition == length) {
            byte[] zero = {(byte)0x00};
            return new MPI(zero);
        } else {
            byte[] trimmedValue = new byte[length - srcPosition];
            System.arraycopy(value, srcPosition, trimmedValue, 0, trimmedValue.length); 
            return new MPI(trimmedValue);
        }
    }

    /** Write to output buffer stream
     * @param stream output buffer stream
     */
    public void write(OutBuf stream) throws OTRException
    {
        stream.writeData(this);
    }
    
    public void writeRaw(OutBuf stream) throws OTRException
    {
        stream.writeRawData(this);
    }

    public byte[] toBytes(){
        byte[] val = this.getValue();
        int len = val.length;
        byte[] ret = new byte[len+4];
        ret[0] = (byte)((len >> 24) & 0xff);
        ret[1] = (byte)((len >> 16) & 0xff);
        ret[2] = (byte)((len >> 8) & 0xff);
        ret[3] = (byte)(len & 0xff);
        
        System.arraycopy(val, 0, ret, 4, len);
        return ret;
    }
    
    /** Checks if this MPI value equals another
     * @param other the other MPI object
     * @return true if the byte sequence value in this MPI equates the other MPI
     */
    public boolean equals(MPI other)
    {
        return super.equals((Data)other);
    }
    /**
     * Converts the long into a byte array of length 4.
     * The result will be in big-endian format.
     * 
     * @param v long value to be converted.
     * @return the byte array corresponding to v.
     */
    public static byte[] toBytes(long v) {
        byte[] result = new byte[8];
        for (int i = 0; i < 8; i++) {
            result[i] = (byte)((v >> (7-i) * 8) & 0xff); 
        }
        return result;
    }
    
    public byte[] getPosValue(){
        byte[] val = this.getValue();
        byte[] posval = new byte[val.length + 1];
        System.arraycopy(val,0,posval,1,val.length);
        return posval;
        
    }
}
