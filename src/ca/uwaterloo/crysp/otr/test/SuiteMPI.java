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

package ca.uwaterloo.crysp.otr.test;
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.crypt.MPI;


public class SuiteMPI extends TestSuite
{
	public SuiteMPI(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "MPI";
	}

	protected void createSuite()
	{
		this.addTestCase(new TestCaseRead(this.harness));
		this.addTestCase(new TestCaseWrite(this.harness));
	}

	private class TestCaseRead extends TestCase
	{
		public TestCaseRead(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			byte[] input = { 
				(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x08, /* 4 byte length */
				(byte)0x00, (byte)0x00, (byte)0x00,  /* leading zeroes */
				(byte)0x01,	(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff /* actual value */
			};
			InBuf stream = new InBuf(input);
			
			MPI mpi = null;
			try {
				mpi = MPI.readMPI(stream);
			} catch (OTRException e) {
				throw new TestException("MPI read failed");
			}

			if(mpi.getLength() != 5) {
				throw new TestException("MPI length mismatch");
			}
			
			byte value[] = mpi.getValue();

			if(value[0] != (byte)0x01
				|| value[1] != (byte)0x2b
				|| value[2] != (byte)0xa4
				|| value[3] != (byte)0x0f
				|| value[4] != (byte)0xff
			) {
				
				throw new TestException("MPI value mismatch");
			}
		}

		public String getDesc()
		{
			return "Read a MPI object from InBuf stream";
		}
	}

	private class TestCaseWrite extends TestCase
	{
		public TestCaseWrite(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			byte[] value = { (byte)0x2b, (byte)0xa4, 
							(byte)0x0f, (byte)0xff};
			MPI mpi = new MPI(value);

			byte[] output = new byte[4 + value.length];
			OutBuf stream = new OutBuf(output);
			try {
				mpi.write(stream);
			} catch (OTRException e) {
				throw new TestException("MPI write failed");
			}

			if(output[0] != (byte)0x00
				|| output[1] != (byte)0x00
				|| output[2] != (byte)0x00
				|| output[3] != (byte)0x04
				|| output[4] != (byte)0x2b
				|| output[5] != (byte)0xa4
				|| output[6] != (byte)0x0f
				|| output[7] != (byte)0xff) {
				
				throw new TestException("MPI value mismatch");
			}
		}

		public String getDesc()
		{
			return "Write a MPI object to OutBuf stream";
		}
	}
}
