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

import java.util.Vector;
import ca.uwaterloo.crysp.otr.iface.OTRTLV;

/**
 * A TLV stores a (type, length, value) tuple.
 * 
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class TLV extends OTRTLV{
    private int type;
    private int len;
    private byte[] value;
    
    /* This is just padding for the encrypted message, and should be ignored. */
    public static final int PADDING=0;
    /* The sender has thrown away his OTR session keys with you */
    public static final int DISCONNECTED=0x0001;

    /* The message contains a step in the Socialist Millionaires' Protocol. */ 
    public static final int SMP1=0x0002;
    public static final int SMP2=0x0003;
    public static final int SMP3=0x0004;
    public static final int SMP4=0x0005;
    public static final int SMP_ABORT=0x0006;
    /* Like OTRL_TLV_SMP1, but there's a question for the buddy at the
     * beginning */
    public static final int SMP1Q=0x0007;

    /** Get the type. */
    public int getType() {
        return type;
    }

    /** Get the length. */
    public int getLength() {
        return len;
    }

    /** Get the serialized length. */
    public int getSerialLength() {
        return len + 4;
    }

    /** Get the value. */
    public byte[] getValue() {
        return value;
    }

    private void init(int type, byte[] value, int offset, int length) {
        this.type = type;
        this.value = new byte[length];
        this.len = length;
        if (length > 0) {
            System.arraycopy(value, offset, this.value, 0, length);
        }
    }

    /** Make a TLV given the pieces. */
    public TLV(int type, byte[] value, int offset, int length) {
        init(type, value, offset, length);
    }

    /** Make a TLV given the pieces. */
    public TLV(int type, byte[] value) {
        init(type, value, 0, value.length);
    }
    
    public TLV(){}

    /** Make a TLV of the given type and size. */
    private TLV(int type, int length) {
        this.type = type;
        this.value = new byte[length];
        this.len = length;
    }

    /** Serialize the TLV into the given buffer. */
    public void serialize(byte[] buf, int offset, int length)
            throws OTRException {
        OutBuf b = new OutBuf(buf, offset, length);
        b.writeShort(type);
        b.writeShort(len);
        b.writeBytes(value);
    }

    /** Serialize the TLV into a newly created buffer. */
    public byte[] serialize() throws OTRException {
        int l = getSerialLength();
        byte[] b = new byte[l];
        serialize(b, 0, l);
        return b;
    }

    /** Serialize an array of TLVs into the given buffer. */
    public byte[] serialize(OTRTLV[] tlvs)
            throws OTRException {
        int len=0;
        for (int j = 0; j < tlvs.length; ++j) {
            len+=((TLV)tlvs[j]).getSerialLength();
        }
        byte[] buf = new  byte[len];
        OutBuf b = new OutBuf(buf);
        for (int j = 0; j < tlvs.length; ++j) {
            b.writeShort(((TLV)tlvs[j]).type);
            b.writeShort(((TLV)tlvs[j]).len);
            b.writeBytes(((TLV)tlvs[j]).value);
        }
        return b.getBytes();
    }

    /** Find the first TLV of the given type. */
    public OTRTLV find(OTRTLV[] tlvs, int type) {
        for (int j = 0; j < tlvs.length; ++j) {
            if (((TLV)tlvs[j]).type == type) {
                return tlvs[j];
            }
        }
        return null;
    }

    /** Construct an array of TLVs from the given data. */
    public OTRTLV[] parse(byte[] buf, int offset, int length)
            throws OTRException {
        InBuf b = new InBuf(buf, offset, length);
        Vector v = new Vector();
        while (b.getLength() > 0) {
            int t = b.readShort();
            int l = b.readShort();
            TLV tlv = new TLV(t, l);
            b.readBytes(tlv.value, 0, l);
            v.addElement(tlv);
        }
        int n = v.size();
        TLV[] tlvs = new TLV[n];
        for (int i = 0; i < n; ++i) {
            tlvs[i] = (TLV) (v.elementAt(i));
        }
        return tlvs;
    }

    /** Construct an array of TLVs from the given data. */
    public OTRTLV[] parse(byte[] buf) throws OTRException {
        return new TLV().parse(buf, 0, buf.length);
    }



    /* Unit tests */

    /*
     * private static void dump(byte[] b) { for (int i=0; i<b.length; ++i) {
     * System.out.print((Integer.toHexString(256 + (b[i] & 0xff))).substring(1)
     * + " "); } }
     * 
     * private void dump() { System.out.print("Type = " + type + " Length = " +
     * len + " Data = ("); dump(value); System.out.println(")"); }
     * 
     * static public void main(String[] args) { new TLV(0, null, 0, 0).dump();
     * new TLV(0, "".getBytes()).dump(); new TLV(1, "".getBytes()).dump(); new
     * TLV(1, "a".getBytes()).dump(); TLV a = new TLV(40000,
     * "abcdef".getBytes()); a.dump(); try { byte[] as = a.serialize();
     * dump(as); System.out.println(""); } catch (OTRException e) {
     * System.out.println("OTRException"); } byte[] bs = { 5, 1, 0, 1, 6, 0, 3,
     * 0, 0, 1, 0, 0, 7, 0, 0, 0, 3, 1, 2, 3 }; try { TLV[] ba = TLV.parse(bs);
     * for (int i=0;i<ba.length;++i) ba[i].dump(); } catch (OTRException e) {
     * System.out.println("OTRException"); } byte[] bs2 = { 5, 1, 0, 1, 6, 0, 3,
     * 0, 0, 1, 0, 0, 8, 0, 0, 0, 3, 1, 2, 3 }; try { TLV[] ba = TLV.parse(bs2);
     * for (int i=0;i<ba.length;++i) ba[i].dump(); } catch (OTRException e) {
     * System.out.println("OTRException"); } }
     */
}
