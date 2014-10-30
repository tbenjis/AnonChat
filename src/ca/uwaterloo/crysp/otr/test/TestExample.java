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
public class TestExample extends TestSuite
{
	public TestExample(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "Example";
	}

	protected void createSuite()
	{
		this.addTestCase(new TestCaseSucceeded(this.harness));
		this.addTestCase(new TestCaseFailed(this.harness));
	}

	private class TestCaseFailed extends TestCase
	{
		public TestCaseFailed(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			throw new TestException("Something bad happened");
		}

		public String getDesc()
		{
			return "A test case that should fail";
		}
	}
	
	private class TestCaseSucceeded extends TestCase
	{
		public TestCaseSucceeded(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			return;
		}

		public String getDesc()
		{
			return "A test case that should succeed";
		}
	}
}
