package commands;

import gui.GuiChatWindow;
import util.ChatWindow;
import core.Buddy;

/**
 * Basically, this allows you to send a message to yourself It identifies your
 * message, or a message you need to send to your contact.
 * 
 * @author tbenjis
 * 
 */
public class in_me {
	public static void command(Buddy buddy, String s, GuiChatWindow w) {

		if (s.length() < 5) {
			ChatWindow.update_window(7, w, "Parameter /me msg", "", "", false);
		} else {
			ChatWindow.update_window(3, w, s.substring(4), "",
					"/me " + s.substring(4), !buddy.isFullyConnected());
		}
	}
}
