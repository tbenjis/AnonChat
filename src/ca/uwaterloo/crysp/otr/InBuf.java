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

package ca.uwaterloo.crysp.otr;

/**
 * Manage input from byte arrays.
 *
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class InBuf {
    /** The buffer */
    private byte[] buf;
    /** The current offset into the buffer */
    private int off;
    /** The remaining length of the buffer */
    private int len;

    /** Get the remaining length. */
    public int getLength() { return len; }


    /** Dump remaining bytes in the buffer
     */
    public void dump()
    {
		dump(1);
    }

	/** Dump bytes in the buffer in groups of set
	 * @param set number in groups
     */
    public void dump(int set)
    {
        for(int i=off; i<buf.length; ) {
			System.out.print("[" + i + "] ");
			for(int j = i + set; i<buf.length && i<j; i++) {
            	System.out.print(OutBuf.hexValue(buf[i]) + " ");
			}
			System.out.println();
        }
    }

    private void init(byte[] buf, int off, int len) {
    this.buf = buf;
    this.off = off;
    this.len = len;
    }

    /** Initialize an OutBuf with a given piece of an array */
    public InBuf(byte[] buf, int off, int len) {
    init(buf, off, len);
    }

    /** Initialize an OutBuf with a given array */
    public InBuf(byte[] buf) {
    init(buf, 0, buf.length);
    }
    
    /**
     * Initialize an OutBuf with the decoded contents of the Base64 input.
     * The input string should start with "OTR?:", followed by the base64 encoded data, ends with ".".
     * @param input Base 64 encoded input. 
     */
    public InBuf(String input) {
    	// Extracts the base64 substring and converts it to the raw byte array
//    	String test = input.substring(5, input.length() - 1);
    	this.buf = Base64Coder.decode(input);
    	this.len = this.buf.length;
    	this.off = 0;
    }

    public int readShort() throws OTRException {
    if (len < 2) throw new OTRException();
    int val = ((buf[off] & 0xff) << 8) 
			+ (buf[off+1] & 0xff);
    off += 2;
    len -= 2;
    return val;
    }

    public void readBytes(byte[] data, int offset, int length)
    throws OTRException {
    if (len < length) throw new OTRException();
    System.arraycopy(buf, off, data, offset, length);
    off += length;
    len -= length;
    }

    public byte[] readBytes(int length) throws OTRException {
    if (len < length) throw new OTRException();
    byte[] b = new byte[length];
    readBytes(b, 0, length);
    return b;
    }

    /** Read and return the next available byte from the buffer
     * @return the next available byte
     */
    public byte readByte() throws OTRException
    {
        if(len < 1) {
            throw new OTRException("input stream has no byte remaining");
        }
        byte value = buf[off];
        ++off;
        --len;
        return value;
    }

    /** Read and return the next unsigned 32 bit integer from the buffer
     * @return the next available unsigned int
     */
    public long readUInt() throws OTRException
    {
        if(len < 4) {
            throw new OTRException("input stream has less than 4 bytes remaining");
        }
        long value = ((buf[off] & 0xff) << 24) 
					+ ((buf[off+1] & 0xff) << 16) 
					+ ((buf[off+2] & 0xff) << 8) 
					+ (buf[off+3] & 0xff);

        off += 4;
        len -= 4;
        return value;
    }
    
    /**
     * Decodes the contents of the buffer and assembles a Data object.
     * @return The assembled Data object.
     * @throws OTRException
     */
    public Data readData() throws OTRException {
		int length = (int)readUInt();
		if(length == 0) {
			// the content of Data cannot be set to null
			// to prevent nullpointer exceptions during serialization
			return new Data(new byte[0]);
		}
		byte[] value = readBytes(length);
		return new Data(value);
    }
}
