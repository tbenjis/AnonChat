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
 * Manage output into byte arrays.
 *
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class OutBuf {
    /** The buffer */
    private byte[] buf;
    /** The current offset into the buffer */
    private int off;
    /** The remaining length of the buffer */
    private int len;
    /** Hex values for printing byte values */
	private	static char[] hex = "0123456789abcdef".toCharArray();

    private void init(byte[] buf, int off, int len) {
	this.buf = buf;
	this.off = off;
	this.len = len;
    }

    /** Initialize an OutBuf with a given piece of an array */
    public OutBuf(byte[] buf, int off, int len) {
	init(buf, off, len);
    }

    /** Initialize an OutBuf with a given array */
    public OutBuf(byte[] buf) {
	init(buf, 0, buf.length);
    }

    public int writeShort(int val) throws OTRException {
	if (len < 2) throw new OTRException();
	buf[off++] = (byte)((val >> 8) & 0xff);
	buf[off++] = (byte)(val & 0xff);
	len -= 2;
	return 2;
    }

    public int writeBytes(byte[] data, int offset, int length)
	throws OTRException {
	if (len < length) throw new OTRException();
	System.arraycopy(data, offset, buf, off, length);
	off += length;
	len -= length;
	return length;
    }

    public int writeBytes(byte[] data) throws OTRException {
	return writeBytes(data, 0, data.length);
	
    }

	/** Writes a byte to the buffer
	 * @param value byte to write
	 */
	public void writeByte(byte value) throws OTRException 
	{
		if(this.len < 1) 
			throw new OTRException("insufficient space in buffer to write a byte");

		this.buf[this.off++] = value;
		--this.len;
	}

	/** Writes 4 bytes of unsigned integer to the buffer
	 * @param value 4 byte unsigned integer to write
	 */
	public void writeUInt(long value) throws OTRException
	{
		if(this.len < 4) 
			throw new OTRException("insufficient space in buffer to write unsigned 4 byte integer");

		this.buf[this.off++] = (byte)((value >> 24) & 0xff);
		this.buf[this.off++] = (byte)((value >> 16) & 0xff);
		this.buf[this.off++] = (byte)((value >> 8) & 0xff);
		this.buf[this.off++] = (byte)(value & 0xff);
		this.len -= 4;
	}
	
	/**
	 * Writes the encoded Data object to the output buffer.
	 * @param val The Data object to be encoded.
	 * @return The number of bytes written to the output buffer.
	 * @throws OTRException
	 */
	public int writeData(Data val) throws OTRException {
		writeUInt(val.getLength());
		writeBytes(val.getValue());
		return 4 + val.getLength();
	}

	public int writeRawData(Data val) throws OTRException {
		writeBytes(val.getValue());
		return 4 + val.getLength();
	}

	/** Dump bytes in the buffer upto offset in groups of set
	 * @param set number in groups
     */
    public void dump(int set)
    {
        for(int i=0; i<buf.length && i<off; ) {
			System.out.print("[" + i + "] ");
			for(int j = i + set; i<buf.length && i<j && i<off; i++) {
            	System.out.print(OutBuf.hexValue(buf[i]) + " ");
			}
			System.out.println();
        }
    }

	/** Dump bytes in the buffer upto offset
	 */
	public void dump()
	{
		dump(1);
	}

	/** Convert byte to hex
	 * @param b byte to convert
	 * @return hex representation of byte
	 */
	public static String hexValue(byte b)
	{
		int left, right;
		right = (b & 0xff)%16; 
		left = ((b & 0xff)/16)%16;
		return "0x" + hex[left] + hex[right]; 
	}
	
	/**
	 * Return the contents of the buffer in Base64 format.
	 * Puts "?OTR:" at the front of the buffer, and '.' at the end.
	 * 
	 * @return The Base64 encoded data.
	 */
	public char[] encodeBase64() { 
		byte[] trimmed = new byte[buf.length - len];
		
		// Extract the necessary bytes from the buffer
		System.arraycopy(buf, 0, trimmed, 0, buf.length - len);
		
		return Base64Coder.encode(trimmed);
	}
	
	public byte[] getBytes() { 
		byte[] trimmed = new byte[buf.length - len];
		// Extract the necessary bytes from the buffer
		System.arraycopy(buf, 0, trimmed, 0, buf.length - len);
		return trimmed;
	}
}
