package commands;

import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.StringTLV;
import gui.GuiChatWindow;
import util.ChatWindow;
import core.Buddy;
import core.Config;
import core.Logger;
import core.otr.ReceivingThread;
/**
 * Display a messeng that was sent by a contact
 * @author tbenjis
 *
 */
public class out_otr {
	public static void command(Buddy buddy, String s, GuiChatWindow w,
			boolean with_delay, OTRInterface us, OTRCallbacks callback) {
		//remove the otr tag
		s = s.substring(5);
		Logger.log(Logger.INFO, "OUT_OTR","From network:"+s.length()+": "+s);
		
		//enable otr
		if(!w.isOTREnabled())
		{
			w.setOTRon();
			//set partial enabled
			w.setPartialEncryption();
			//generate keys for otr
			w.generateOTRkeys();
			//start the receive thread
			new ReceivingThread(buddy, s, w, us, callback).start();	
		}
		
		
		
	}
}