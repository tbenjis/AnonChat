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

/** Generic State Machine class
 */
public abstract class StateMachine
{
	// Indicates no transition occured on processEvent()
	public static final int NO_TRANSITION = -2;	

	protected int initState;			// initial state
	protected int curState;				// current state

	/** Constructor
	 */
	public StateMachine()
	{
	}

	/** Resets the state machine to its initial state
	 */
	public void reset()
	{	
		this.curState = this.initState;
	}

	/** Get the current state
	 * @return current state of the state machine
	 */
	public int getCurState()
	{
		return this.curState;
	}

	/** Process state transitions based on input event.
	 * @param event the event to process
	 * @return the new state after processing event, 
	 * 			otherwise NO_TRANSITION
	 */
	public abstract int processEvent(int event);
}
