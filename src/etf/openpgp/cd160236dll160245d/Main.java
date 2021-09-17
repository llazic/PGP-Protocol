package etf.openpgp.cd160236dll160245d;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.security.Security;

import javax.swing.AbstractAction;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
	public static JFrame frame;
	public static JPanel secretKeyRingPanel;
	public static JPanel pubKeyRingPanel;

	@SuppressWarnings("serial")
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		frame = new JFrame("OpenPGP");
		frame.getContentPane().setLayout(new BorderLayout(0, 0));

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);

		secretKeyRingPanel = new JPanel(new BorderLayout());
		tabbedPane.addTab("Secret Key Ring", secretKeyRingPanel);
		SecretKeys.listSecretKeys(secretKeyRingPanel);

		pubKeyRingPanel = new JPanel(new GridLayout(0, 1));
		tabbedPane.addTab("Public Key Ring", pubKeyRingPanel);
		PublicKeys.listPublicKeys(pubKeyRingPanel);

		frame.getContentPane().add(tabbedPane, BorderLayout.CENTER);

		JMenuBar menuBar = new JMenuBar();
		frame.setJMenuBar(menuBar);

		JMenu mnFile = new JMenu("File");
		menuBar.add(mnFile);

		JMenuItem mntmGenerateKeyPair = new JMenuItem(new AbstractAction("Generate Key Pair") {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				while (SecretKeys.generateNewKeyPairDialog() == false) {
					JOptionPane.showMessageDialog(null, "You should enter data into every field!");
				}
			}
		});
		mnFile.add(mntmGenerateKeyPair);
		
		JMenuItem mntmRemoveKeyPair = new JMenuItem(new AbstractAction("Remove Key Pair") {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				SecretKeys.removeKeyPair();
			}
		});
		mnFile.add(mntmRemoveKeyPair);

		mnFile.addSeparator();

		JMenuItem mntmImportPublicKey = new JMenuItem(new AbstractAction("Import Public Key") {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				PublicKeys.importPublicKey();
			}
		});
		mnFile.add(mntmImportPublicKey);
		
		JMenuItem mntmImportKeyPair = new JMenuItem(new AbstractAction("Import Key Pair") {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				SecretKeys.importKeyPair();
			}
		});
		mnFile.add(mntmImportKeyPair);
		
		JMenuItem mntmExportPublicKey = new JMenuItem(new AbstractAction("Export Public Key") {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				PublicKeys.exportPublicKey();
			}
		});
		mnFile.add(mntmExportPublicKey);
		
		JMenuItem mntmExportKeyPair = new JMenuItem(new AbstractAction("Export Key Pair") {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				SecretKeys.exportKeyPair();
			}
		});
		mnFile.add(mntmExportKeyPair);
		
		mnFile.addSeparator();
		
		JMenuItem mntmSendMessage = new JMenuItem(new AbstractAction("Send Message") {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				SendMessage.send();
			}
		});
		mnFile.add(mntmSendMessage);
		

		JMenuItem mntmReceiveMessage = new JMenuItem(new AbstractAction("Receive Message") {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				ReceiveMessage.receive();
			}
		});
		mnFile.add(mntmReceiveMessage);
		

		frame.setBounds(600, 250, 700, 500);
		frame.setVisible(true);
		frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
	}
}
