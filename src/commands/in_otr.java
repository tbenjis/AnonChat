package commands;

import gui.GuiChatWindow;
import util.ChatWindow;
import core.Buddy;
/**
 * Display a messeng that was sent by a contact
 * @author tbenjis
 *
 */
public class in_otr {
	public static void command(Buddy buddy, String s, GuiChatWindow w) {
		String msg = " from "+buddy.toString();
		ChatWindow.update_window(5, w, s.substring(5)+msg, "", s, !buddy.isFullyConnected());
	}
}