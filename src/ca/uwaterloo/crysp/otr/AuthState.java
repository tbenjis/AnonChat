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

/** Class to encapsulate state transitions for authenticated key exchange
 */
public class AuthState extends StateMachine
{
	// States
	public static final int ST_NONE 				= 0;
	public static final int ST_AWAITING_DHKEY 		= 1;
	public static final int ST_AWAITING_REVEALSIG 	= 2;
	public static final int ST_AWAITING_SIG 		= 3;

	// Events
	public static final int EVT_DH_COMMIT_SENT 	= 0;
	public static final int EVT_DH_COMMIT_RCVD 	= 1;
	public static final int EVT_DH_KEY_SENT 	= 2;
	public static final int EVT_DH_KEY_RCVD   = 3;
	public static final int EVT_REVEALSIG_SENT 	= 4;
	public static final int EVT_REVEALSIG_RCVD 	= 5;
	public static final int EVT_SIG_SENT 		= 6;
	public static final int EVT_SIG_RCVD 		= 7;


	/* Constructor
	 */
	public AuthState()
	{
		initState = ST_NONE;
		reset();
	}

	//TODO
	/** Process state transitions based on input event.
	 * @param event the event to process
	 * @return the new state after processing event, 
	 * 			otherwise NO_TRANSITION
	 */
	public int processEvent(int event)
	{
		int oldState = this.curState;
		switch(this.curState) {
			case ST_NONE:
				if(event == EVT_DH_COMMIT_SENT) {
					this.curState = ST_AWAITING_DHKEY;
				}
				if(event == EVT_DH_KEY_SENT) {
					this.curState = ST_AWAITING_REVEALSIG;
				}
				break;

			case ST_AWAITING_DHKEY:
				if(event == EVT_REVEALSIG_SENT) {
					this.curState = ST_AWAITING_REVEALSIG;
				}
				if(event == EVT_DH_KEY_RCVD){
					this.curState = ST_AWAITING_SIG;
				}
				break;

			case ST_AWAITING_REVEALSIG:
				if(event == EVT_REVEALSIG_RCVD) {
					this.reset();
				}
				if(event == EVT_DH_KEY_RCVD){
					this.curState = ST_AWAITING_SIG;
				}
				break;

			case ST_AWAITING_SIG:
				if(event == EVT_SIG_RCVD) {
					this.reset();
				}
				if(event == EVT_DH_KEY_SENT){
					this.curState = ST_AWAITING_REVEALSIG;
				}
				break;
		}

		if(this.curState != oldState) {
			return this.curState;
		}

		return StateMachine.NO_TRANSITION;
	}
}
