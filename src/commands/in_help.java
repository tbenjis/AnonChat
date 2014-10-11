package commands;

import util.ChatWindow;
import gui.GuiChatWindow;
import core.Buddy;
import core.language;

/**
 * This is the help command
 * 
 * @author tbenjis
 * 
 */
public class in_help {
	public static void command(Buddy buddy, String s, GuiChatWindow w) {

		String help;

		help = "\n" + language.langtext[57] + "\n";
		help += "/help (Shows this menu)\n";
		help += "/me (Send a message to yourself)\n";
		help += "/log (Saves current conversation)\n";

		ChatWindow.update_window(7, w, help, "", "", false);

	}
}
