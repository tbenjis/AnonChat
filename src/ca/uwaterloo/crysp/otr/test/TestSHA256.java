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

import ca.uwaterloo.crysp.otr.crypt.*;

public class TestSHA256 extends TestSuite
{
	private Provider prov;
	public TestSHA256(TestHarness h, Provider prov)
	{
		super(h);
		this.prov=prov;
		createSuite();
	}
	
	public String getName()
	{
		return "SHA256";
	}

	protected void createSuite()
	{
		this.addTestCase(new TestCaseSHA256NoOptionalParameters(this.harness));
		this.addTestCase(new TestCaseSHA256WithOptionalParameters(this.harness));
		this.addTestCase(new TestCaseSHA256Multiple(this.harness));
		this.addTestCase(new TestCaseSHA256Invalid(this.harness));
		this.addTestCase(new TestCaseSHA256Update(this.harness));
	}
	
	
	private class TestCaseSHA256NoOptionalParameters extends TestCase
	{
		public TestCaseSHA256NoOptionalParameters(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			try {
		
				SHA256 d = prov.getSHA256();
				byte[] s = d.hash("hi".getBytes());
				boolean r = d.verify(s, "hi".getBytes());
				
				if(!r) {
					throw new RuntimeException("Message could not be verified");
				}
			} catch (OTRCryptException e) {
				throw new TestException(e.getMessage());
			}
		}

		public String getDesc()
		{
			return "Digest verification with no optional parameters";
		}
	}
	
	private class TestCaseSHA256WithOptionalParameters extends TestCase
	{
		public TestCaseSHA256WithOptionalParameters(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			try {
				SHA256 d = prov.getSHA256();				
				byte[] message = "Hello World".getBytes();
				
				byte[] s = d.hash(message, 2, 5);
				boolean r = d.verify(s, message, 2, 5);
				
				if(!r) {
					throw new RuntimeException("Message could not be verified");
				}
			} catch (OTRCryptException e) {
				throw new TestException(e.getMessage());
			}
		}

		public String getDesc()
		{
			return "Digest verification with length and offset specified";
		}
	}
	
	private class TestCaseSHA256Multiple extends TestCase
	{
		public TestCaseSHA256Multiple(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			try {
			
				SHA256 d = prov.getSHA256();				
				byte[] message = "Hello World".getBytes();
				byte[] message2 = "This is my 2nd message".getBytes();
				
				byte[] s = d.hash(message, 2, 5);
				boolean r = d.verify(s, message, 2, 5);
				
				if(!r) {
					throw new RuntimeException("Message could not be verified");
				}
				
				s = d.hash(message);
				r = d.verify(s, message);
				if(!r) {
					throw new RuntimeException("Message could not be verified");
				}
				
				s = d.hash(message2);
				r = d.verify(s, message2);
				if(!r) {
					throw new RuntimeException("Message could not be verified");
				}
				
				s = d.hash(message2, 3, 7);
				r = d.verify(s, message2, 3, 7);
				if(!r) {
					throw new RuntimeException("Message could not be verified");
				}
			} catch (OTRCryptException e) {
				throw new TestException(e.getMessage());
			}
		}

		public String getDesc()
		{
			return "Hashing and verifying data multiple times";
		}
	}
	
	private class TestCaseSHA256Invalid extends TestCase
	{
		public TestCaseSHA256Invalid(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			try {
				SHA256 d = prov.getSHA256();				
				byte[] message = "This is my test message".getBytes();
				
				byte[] s = d.hash(message);
				// Alter the bytes a bit
				s[0]++;
				s[1]--;
				boolean r = d.verify(s, message);
				
				if(r) {
				    throw new RuntimeException("Message was erraneously accepted");
				}
				
				// Restore the original signature, signature should be accepted
				s[0]--;
				s[1]++;
				r = d.verify(s, message);
				if (!r) {
					throw new RuntimeException("Message was erraneously rejected");
				}
				
			} catch (OTRCryptException e) {
				throw new TestException(e.getMessage());
			}
		}

		public String getDesc()
		{
			return "Invalid signature detection";
		}
	}
	private class TestCaseSHA256Update extends TestCase{
		
		public TestCaseSHA256Update(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			try {
			
				SHA256 d = prov.getSHA256();				
				byte[] message = "Hello ".getBytes();
				byte[] message2 = "world".getBytes();
				
				d.update(message);
				d.update(message2);
				byte[] s = d.hash();
				d.hash("Hello world".getBytes());
				boolean r = d.verify(s, "Hello world".getBytes());
				
				if(!r) {
					throw new RuntimeException("Message could not be verified");
				}
			} catch (OTRCryptException e) {
				throw new TestException(e.getMessage());
			}
		}

		public String getDesc()
		{
			return "Hashing and verifying data using update";
		}
	}
}
