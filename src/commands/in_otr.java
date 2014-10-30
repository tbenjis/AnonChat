package commands;

import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import gui.GuiChatWindow;
import util.ChatWindow;
import core.Buddy;
/**
 * Display a messeng that was sent by a contact
 * @author tbenjis
 *
 */
public class in_otr {
	public static void command(Buddy buddy, String s, GuiChatWindow w, OTRInterface us, OTRCallbacks callback) {
		ChatWindow.update_window(5, w, s.substring(5), "", s, !buddy.isFullyConnected());
	}
}