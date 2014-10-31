package commands;

import javax.swing.JOptionPane;

import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRContext;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.Policy;
import gui.GuiChatWindow;
import util.ChatWindow;
import core.Buddy;
import core.Config;
import core.Logger;
/**
 * Display a messing that we send
 * @author tbenjis
 *
 */
public class in_otr {
	public static void command(Buddy buddy, String s, GuiChatWindow w, OTRInterface us, OTRCallbacks callback, OTRContext conn) {
				
		//get the next 5 string
		String str = s.substring(5);
		Logger.log(Logger.INFO, "IN_OTR", Config.us+" "+buddy.getClient()+" "+buddy.getAddress());
		try {
			
			if(str.startsWith("/isq")){
				Logger.log(Logger.INFO, "IN_OTR","Requesting Secret question");
				String question = JOptionPane.showInputDialog("Please input secret question");
				Logger.log(Logger.INFO, "IN_OTR","Accepting Secret answer");
				str = JOptionPane.showInputDialog("Please input the secret");
				conn.initiateSmp_q(question, str, callback);
			}else if(str.startsWith("/is")){
				Logger.log(Logger.INFO, "IN_OTR","initiating SMP");
				str = JOptionPane.showInputDialog("Please input the secret");
				conn.initiateSmp(str, callback);
			}else if(str.startsWith("/rs")){
				Logger.log(Logger.INFO, "IN_OTR","Accepting Secret answer from buddy");
				str = JOptionPane.showInputDialog("Please input the secret");
				conn.respondSmp(str, callback);
			}else if(str.startsWith("/as")){
				Logger.log(Logger.INFO, "IN_OTR","Aborting SMP");
				conn.abortSmp(callback);
			}else if(str.startsWith("/disc")){
				Logger.log(Logger.INFO, "IN_OTR","Disconnecting encryption");
				conn.disconnect(callback);
			}
			else{
				Logger.log(Logger.INFO,"IN_OTR","Converting to OTR:"+str.length()+":"+str);
				//OTRTLV[] tlvs = new OTRTLV[1];
				//tlvs[0]=new TLV(9, "TestTLV".getBytes());
				str = us.messageSending(Config.us, buddy.getClient(), buddy.getAddress(),
						str, null, Policy.FRAGMENT_SEND_ALL, callback);
				if (str == null){
					Logger.log(Logger.SEVERE, "IN_OTR","Failure Encrypting message");
					
				}else{
					// show message encryption error
					JOptionPane.showMessageDialog(null, "Message not encrypted, an error occured");
				}
				//Logger.log(Logger.INFO, "IN_OTR",result);
				/*if(str.length()!=0){
					Logger.log(Logger.INFO, "IN_OTR","To network:"+str.length()+":"+str+"");
					//conn.fragmentAndSend(str,  callback);
				}*/
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		//add otr tag
		ChatWindow.update_window(5, w, str, "", "/otr "+str, !buddy.isFullyConnected());
	}
}