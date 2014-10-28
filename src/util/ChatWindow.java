package util;

import java.io.FileOutputStream;
import java.io.IOException;

import core.Config;
import core.TCPort;
import gui.GuiChatWindow;

public class ChatWindow {

	// update_window(type, w,new_entry,new_textarea,send,add_delay) {
	/**
	 * Append messages on the chat window
	 * @param type 1=Normal message from me, 2=Normal message form them,
	 * 3=A message from me, 4=A message from them, 5=OTR request
	 * @param w
	 * @param new_entry
	 * @param new_textarea
	 * @param send
	 * @param add_delay
	 */

	public static void update_window(int type, GuiChatWindow w,
			String new_entry, String new_textarea, String send,
			boolean add_delay) {
		String delay = "";

		if (add_delay) {
			delay = "[Delayed] ";
		}

		// Not in use but useful
		if (type == 0) {
		}
		// Send or receive a normal Message
		else if (type == 1) {
			w.append("Time Stamp", "(" + GuiChatWindow.getTime() + ") ");
			w.append("Me", delay + "Me: ");
			w.addUrlText("Plain", new_entry + "\n");
		} else if (type == 2) {
			w.append("Time Stamp", "(" + GuiChatWindow.getTime() + ") ");
			w.append("Them", delay + "Them: ");
			w.addUrlText("Plain", new_entry + "\n");
		}
		// Send or receive what you or the other do
		else if (type == 3) {
			w.append("Time Stamp", "(" + GuiChatWindow.getTime() + ") ");

			if (TCPort.profile_name != "") {
				w.append("Me", delay + "* " + TCPort.profile_name + " ");
			} else {
				w.append("Me", delay + "* " + Config.us + " ");
			}
			w.addUrlText("Plain", new_entry + "\n");
		} else if (type == 4) {
			w.append("Time Stamp", "(" + GuiChatWindow.getTime() + ") ");
			w.append("Them", delay + "* " + w.b.toString() + " ");
			w.addUrlText("Plain", new_entry + "\n");
		}
		// Send or receive OTR request
		else if (type == 5) {
			w.append("Time Stamp", "(" + GuiChatWindow.getTime() + ") ");
			w.append("Me", delay + "Me <<OTR>> ");
			w.addUrlText("Me", new_entry.trim() + "\n");
		//incomming OTR message
		} else if (type == 6) {
			w.append("Time Stamp", "(" + GuiChatWindow.getTime() + ") ");
			w.append("Them", delay + "* " +  w.b.toString()+" <<OTR>> ");
			w.addUrlText("Them", new_entry + "\n");
		}
		// Private
		else if (type == 7) {
			w.append("Time Stamp", "(" + GuiChatWindow.getTime() + ") ");
			w.append("Me", delay + "Private: ");
			w.addUrlText("Plain", new_entry + "\n");
		}

		w.get_textPane1().setCaretPosition(
				w.get_textPane1().getDocument().getLength());

		if (new_textarea != null) {
			w.get_textArea4().setText(new_textarea);
		}
		w.get_textArea4().requestFocusInWindow();

		if (send != "") {

			send = send.trim().replaceAll("\n", "\\\\n").replaceAll("\r", "");

			try {
				if (!add_delay) {
					//sends the message
					w.b.sendMessage(send);
				} else {
					FileOutputStream fos = new FileOutputStream(
							Config.MESSAGE_DIR + w.b.getAddress() + ".txt",
							true);
					fos.write(("[Delayed] " + send + "\n").getBytes());
					fos.close();
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

}
