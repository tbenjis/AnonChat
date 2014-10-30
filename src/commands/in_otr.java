package commands;

import javax.swing.JOptionPane;

import ca.uwaterloo.crysp.otr.TLV;
import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRContext;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.OTRTLV;
import ca.uwaterloo.crysp.otr.iface.Policy;
import gui.GuiChatWindow;
import util.ChatWindow;
import core.Buddy;
import core.Config;
/**
 * Display a messeng that was sent by a contact
 * @author tbenjis
 *
 */
public class in_otr {
	public static void command(Buddy buddy, String s, GuiChatWindow w, OTRInterface us, OTRCallbacks callback) {
		OTRContext conn;
		
		//get the next 5 string
		String str = s.substring(5);
		conn=us.getContext(Config.us, buddy.getClient(), buddy.getAddress());
		try {
			
			if(str.startsWith("/isq")){
				System.out.println("Please input the question");
				String question = JOptionPane.showInputDialog("Please input secret question");
				str = JOptionPane.showInputDialog("Please input the secret");
				conn.initiateSmp_q(question, str, callback);
			}else if(str.startsWith("/is")){
				str = JOptionPane.showInputDialog("Please input the secret");
				conn.initiateSmp(str, callback);
			}else if(str.startsWith("/rs")){
				str = JOptionPane.showInputDialog("Please input the secret");
				conn.respondSmp(str, callback);
			}else if(str.startsWith("/as")){
				conn.abortSmp(callback);
			}else if(str.startsWith("/disc")){
				conn.disconnect(callback);
			}
			else{
				System.out.println("\033[31mTo OTR:"+str.length()+":\033[0m"+str);
				OTRTLV[] tlvs = new OTRTLV[1];
				tlvs[0]=new TLV(9, "TestTLV".getBytes());
				us.messageSending(Config.us, buddy.getClient(), buddy.getAddress(),
						str, tlvs, Policy.FRAGMENT_SEND_ALL, callback);
				/*if(str.length()!=0){
					System.out.println("\033[31mTo network:"+str.length()+":\033[35m"+str+"\033[0m");
					conn.fragmentAndSend(str,  callback);
				}*/
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		ChatWindow.update_window(5, w, s.substring(5), "", s, !buddy.isFullyConnected());
	}
}