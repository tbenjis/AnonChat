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
import java.util.Vector;


public abstract class TestSuite implements ITest
{
        private Vector testCases;               // test cases in the test suite
        protected TestHarness harness;  // the test harness to notify

        protected abstract void createSuite();
        protected abstract String getName();

        public TestSuite(TestHarness h)
        {
                this.harness = h;
                this.testCases = new Vector();
        }

        protected final void addTestCase(ITest t)
        {
                this.testCases.addElement(t);
        }
        
        public String run()
        {
                String ret=
                        this.harness.notifyTestSuite(this.getName(), this.testCases.size());
                ITest t;
                for(int i=0; i<this.testCases.size(); ++i) {
                        t = (ITest)this.testCases.elementAt(i);
                        ret+= t.run();
                }
                return ret;
        }
}
