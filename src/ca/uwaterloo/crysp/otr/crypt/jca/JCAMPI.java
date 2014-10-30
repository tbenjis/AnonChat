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

package ca.uwaterloo.crysp.otr.crypt.jca;

import java.math.BigInteger;
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.OTRException;

/**
 * Helper routines for multi-precision integers.
 *
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class JCAMPI extends ca.uwaterloo.crysp.otr.crypt.MPI{
	
    public JCAMPI(byte[] value) {
		super(value);
	}
    
    public static ca.uwaterloo.crysp.otr.crypt.MPI toMPI(BigInteger val) throws OTRException{
    	byte[] v = toBytes(val);
    	ca.uwaterloo.crysp.otr.crypt.MPI ret = 
    		ca.uwaterloo.crysp.otr.crypt.MPI.readMPI(new InBuf(v));
    	return ret;
    }
    
    public static BigInteger getBigInteger(ca.uwaterloo.crysp.otr.crypt.MPI mpi){
    	byte[] val = mpi.getValue();
    	if(val.length==1 && val[0]==(byte)0){
    		return BigInteger.valueOf(0);
    	}
    	byte[] ret = new byte[val.length+1];
    	System.arraycopy(val, 0, ret, 1, val.length);
    	return new BigInteger(ret);
    }
    
    
	/** Convert a BigInteger to a standard byte[] format.  Outputs four
     * bytes of length (big-endian), followed by that many bytes of
     * big-endian data.  Leading 0 bytes are removed, and the data is
     * always treated as unsigned.
     */
   public static byte[] toBytes(BigInteger v) {
		byte[] ba = v.toByteArray();
		// Skip leading 0 bytes
		int start = 0;
		int len = ba.length;
		while(len > 0 && ba[start] == 0) {
		    ++start;
		    --len;
		}
		byte[] n = new byte[len + 4];
		n[0] = (byte)((len >> 24) & 0xff);
		n[1] = (byte)((len >> 16) & 0xff);
		n[2] = (byte)((len >> 8) & 0xff);
		n[3] = (byte)(len & 0xff);
		System.arraycopy(ba, start, n, 4, len);
	
		return n;
    }
   
   public static byte[] toTrimmedBytes(BigInteger v) {
		byte[] ba = v.toByteArray();
		// Skip leading 0 bytes
		int start = 0;
		int len = ba.length;
		while(len > 0 && ba[start] == 0) {
		    ++start;
		    --len;
		}
		byte[] n = new byte[len];
		System.arraycopy(ba, start, n, 0, len);
	
		return n;
   }
   
   
   public static void toOutBuf(BigInteger v, OutBuf ob) throws OTRException{
	   byte[] content = toBytes(v);
	   ob.writeBytes(content);
   }
    /**
     * Converts the byte array to a BigInteger object.
     * The first 4 bytes indicate the length of the rest
     * of the data. The length as well as the actual value
     * of the BigInteger object is interpreted as big-endian.
     * 
     * @return a BigInteger containing the value as specified by input.
     */
    public static BigInteger fromBytes(byte[] input) {
    	BigInteger result;
    	
    	int len = 0;
    	len += ((byte)input[0] & 0xff) << 24;
    	len += ((byte)input[1] & 0xff) << 16;
    	len += ((byte)input[2] & 0xff) << 8;
    	len += ((byte)input[3] & 0xff);
    	if (len == 0) return BigInteger.valueOf(0);
    	
    	byte[] n = new byte[len+1];
    	// First byte = 0 to indicate the number is unsigned
    	n[0] = 0x00;
    	System.arraycopy(input, 4, n, 1, len);
    	result = new BigInteger(n);

    	return result;
    }
    
    public static BigInteger fromTrimmedBytes(byte[] input) {
    	BigInteger result;
    	
    	int len = input.length;
    	if (len == 0) return BigInteger.valueOf(0);
    	
    	byte[] n = new byte[len+1];
    	// First byte = 0 to indicate the number is unsigned
    	n[0] = 0x00;
    	System.arraycopy(input, 0, n, 1, len);
    	result = new BigInteger(n);
    	return result;
    }
    
    
    /**
     * Read a BigInteger object from InBuf.
     * The first 4 bytes indicate the length of the rest
     * of the data. The length as well as the actual value
     * of the BigInteger object is interpreted as big-endian.
     * 
     * @return a BigInteger containing the value as specified by input.
     * @throws OTRException 
     */
    public static BigInteger fromInBuf(InBuf input) throws OTRException {
    	BigInteger result;
    	byte[] lenbyte = input.readBytes(4);
    	int len = 0;
    	len += ((byte)lenbyte[0] & 0xff) << 24;
    	len += ((byte)lenbyte[1] & 0xff) << 16;
    	len += ((byte)lenbyte[2] & 0xff) << 8;
    	len += ((byte)lenbyte[3] & 0xff);
    	if (len == 0) return BigInteger.valueOf(0);
    	
    	byte[] n = new byte[len+1];
    	// First byte = 0 to indicate the number is unsigned
    	n[0] = 0x00;
    	byte[] content = input.readBytes(len);
    	System.arraycopy(content, 0, n, 1, len);
    	result = new BigInteger(n);

    	return result;
    }
}
