package commands;

import gui.GuiChatWindow;
import util.ChatWindow;
import core.Buddy;
/**
 * Display a messeng that was sent by a contact
 * @author tbenjis
 *
 */
public class out_me {
	public static void command(Buddy buddy, String s, GuiChatWindow w,
			boolean with_delay) {
		ChatWindow.update_window(4, w, s.substring(4), "", "", with_delay);
	}
}