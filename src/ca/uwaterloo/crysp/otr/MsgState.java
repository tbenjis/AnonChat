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

/** Class to encapsulate control of outgoing messages
 */
public class MsgState extends StateMachine
{
	// States
	public static final int ST_UNENCRYPTED 	= 0;
	public static final int ST_ENCRYPTED 	= 1;
	public static final int ST_FINISHED 	= 2;

	// Events
	public static final int EVT_AUTHENTICATED 	= 0;
	public static final int EVT_TERMINATED 		= 1;
	public static final int EVT_SWITCH_PLAIN 	= 2;

	/* Constructor
	 */
	public MsgState()
	{
		initState = ST_UNENCRYPTED;
		reset();
	}

	/** Process state transitions based on input event.
	 * @param event the event to process
	 * @return the new state after processing event, 
	 * 			otherwise NO_TRANSITION
	 */
	public int processEvent(int event)
	{
		int oldState = this.curState;
		switch(this.curState) {
			case ST_UNENCRYPTED:
				if(event == EVT_AUTHENTICATED) {
					this.curState = ST_ENCRYPTED;
				}
				break;
			case ST_ENCRYPTED:
				if(event == EVT_TERMINATED) {
					this.curState = ST_FINISHED;
				}
				break;
			case ST_FINISHED:
				if(event == EVT_SWITCH_PLAIN) {
					this.curState = ST_UNENCRYPTED;
				}
				break;
		}

		if(this.curState != oldState) {
			return this.curState;
		}

		return StateMachine.NO_TRANSITION;
	}
}
