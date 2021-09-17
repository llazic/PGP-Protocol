package etf.openpgp.cd160236dll160245d;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class PublicKeys {
	@SuppressWarnings("rawtypes")
	public static void listPublicKeys(JPanel panel) {
		String[] columnNames = { "Name", "EMail", "Timestamp", "KeyID" };

		try {
			File secretFile = new File("pub.asc");
			secretFile.createNewFile(); // if file already exists will do nothing 
			
			PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(
					PGPUtil.getDecoderStream(new FileInputStream("pub.asc")), new JcaKeyFingerprintCalculator());

			Iterator rIt = pubRings.getKeyRings();
			Object[][] data = new Object[pubRings.size()][4];
			int i = 0;

			while (rIt.hasNext()) {
				PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();

				try {
					pgpPub.getPublicKey();
				} catch (Exception e) {
					e.printStackTrace();
					continue;
				}

				Iterator it = pgpPub.getPublicKeys();
				PGPPublicKey pgpKey = (PGPPublicKey) it.next();

				// panel.add(); moze drugacije da izgleda identity
				String identity = new String(pgpKey.getRawUserIDs().next());
				String[] array = identity.split(" ");
				data[i][0] = array[0];
				data[i][1] = array[1].substring(1, array[1].length() - 1);

				data[i][2] = pgpKey.getPublicKeyPacket().getTime().toString();
				data[i][3] = Long.toHexString(pgpKey.getKeyID());

				i++;
			}

			JTable table = new JTable(data, columnNames);
			JScrollPane jScrollPane = new JScrollPane(table);
			panel.add(jScrollPane, BorderLayout.CENTER);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// ovde izvozimo public kljuc bilo iz secret ringa bilo iz public ringa
	@SuppressWarnings("rawtypes")
	public static void exportPublicKey() {
		PGPSecretKeyRingCollection secretRings;
		PGPPublicKeyRingCollection pubRings;
		try {
			secretRings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(new FileInputStream("secret.asc")),
					new JcaKeyFingerprintCalculator());
			
			pubRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(new FileInputStream("pub.asc")),
					new JcaKeyFingerprintCalculator());

			Iterator rIt = secretRings.getKeyRings();
			// Object[][] data = new Object[secretRings.size()][4];
			PGPSecretKeyRing[] secretKeyRingArray = new PGPSecretKeyRing[secretRings.size()];
			String[] secretKeyRingStrings = new String[secretRings.size() + pubRings.size()];
			int i = 0;

			while (rIt.hasNext()) {
				PGPSecretKeyRing pgpSecret = (PGPSecretKeyRing) rIt.next();
				secretKeyRingArray[i] = pgpSecret;

				try {
					pgpSecret.getPublicKey();
				} catch (Exception e) {
					e.printStackTrace();
					continue;
				}

				Iterator it = pgpSecret.getPublicKeys();
				PGPPublicKey pgpKey = (PGPPublicKey) it.next();

				// panel.add();
				String identity = new String(pgpKey.getRawUserIDs().next());
				String[] array = identity.split(" ");

				secretKeyRingStrings[i] = array[0] + ", " + array[1].substring(1, array[1].length() - 1) + ", "
						+ Long.toHexString(pgpKey.getKeyID());

				i++;
			}
			
			rIt = pubRings.getKeyRings();
			// Object[][] data = new Object[secretRings.size()][4];
			PGPPublicKeyRing[] publicKeyRingArray = new PGPPublicKeyRing[pubRings.size()];
			
			while (rIt.hasNext()) {
				PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();
				publicKeyRingArray[i - secretRings.size()] = pgpPub;

				try {
					pgpPub.getPublicKey();
				} catch (Exception e) {
					e.printStackTrace();
					continue;
				}

				Iterator it = pgpPub.getPublicKeys();
				PGPPublicKey pgpKey = (PGPPublicKey) it.next();

				// panel.add();
				String identity = new String(pgpKey.getRawUserIDs().next());
				String[] array = identity.split(" ");

				secretKeyRingStrings[i] = array[0] + ", " + array[1].substring(1, array[1].length() - 1) + ", "
						+ Long.toHexString(pgpKey.getKeyID());

				i++;
			}
			

			JComboBox<String> secretKeysCombo = new JComboBox<>(secretKeyRingStrings);
			JPanel panel = new JPanel(new GridLayout(0, 1));
			panel.add(new JLabel("Choose public key to export:"));
			panel.add(secretKeysCombo);

			int result = JOptionPane.showConfirmDialog(null, panel, "Export", JOptionPane.OK_CANCEL_OPTION,
					JOptionPane.PLAIN_MESSAGE);

			if (result == JOptionPane.OK_OPTION) {
				int selectedIndex = secretKeysCombo.getSelectedIndex();
				PGPKeyRing selectedKeyRing = null;
				if (selectedIndex < secretRings.size()) {
					//u pitanju je secret key ring
					selectedKeyRing = secretKeyRingArray[selectedIndex];
				} else {
					//u pitanju je public key ring
					selectedKeyRing = publicKeyRingArray[selectedIndex - secretRings.size()];
					
				}
				List<PGPPublicKey> publicKeyList = new ArrayList<PGPPublicKey>();
				Iterator<PGPPublicKey> iterator = selectedKeyRing.getPublicKeys();
				publicKeyList.add(iterator.next());
				publicKeyList.add(iterator.next());
				PGPPublicKeyRing ringToExport = new PGPPublicKeyRing(publicKeyList);
				//PGPPublicKey selectedPublicKey = selectedKeyRing.getPublicKey();

				JFrame parentFrame = new JFrame();

				JFileChooser fileChooser = new JFileChooser();
				fileChooser.setDialogTitle("Specify a file to save");

				int userSelection = fileChooser.showSaveDialog(parentFrame);

				if (userSelection == JFileChooser.APPROVE_OPTION) {
					File fileToSave = fileChooser.getSelectedFile();
					System.out.println("Save as file: " + fileToSave.getAbsolutePath());

					OutputStream secretOut = new FileOutputStream(fileToSave.getAbsolutePath() + ".asc");
					secretOut = new ArmoredOutputStream(secretOut);
					ringToExport.encode(secretOut);
					secretOut.close();

					JOptionPane.showMessageDialog(null, "Public key successfully exported!");
				}
			} else {
				System.out.println("Cancelled!");
			}
		} catch (IOException | PGPException e1) {
			e1.printStackTrace();
		}
	}

	@SuppressWarnings("rawtypes")
	public static void importPublicKey() {
		JFrame parentFrame = new JFrame();

		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Specify a file to import");

		int userSelection = fileChooser.showSaveDialog(parentFrame);

		if (userSelection == JFileChooser.APPROVE_OPTION) {
			File fileToOpen = fileChooser.getSelectedFile();

			try {
				PGPPublicKeyRingCollection pubRingsToImport = new PGPPublicKeyRingCollection(
						PGPUtil.getDecoderStream(new FileInputStream(fileToOpen.getAbsolutePath())),
						new JcaKeyFingerprintCalculator());

				PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(
						PGPUtil.getDecoderStream(new FileInputStream("pub.asc")), new JcaKeyFingerprintCalculator());

				Iterator rIt = pubRingsToImport.getKeyRings();
				int i = 0;
				boolean alreadyExist = false;
				while (rIt.hasNext()) {
					PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();

					try {
						pgpPub.getPublicKey();
					} catch (Exception e) {
						e.printStackTrace();
						continue;
					}
					try {
						pubRings = PGPPublicKeyRingCollection.addPublicKeyRing(pubRings, pgpPub);
					} catch (IllegalArgumentException e) {
						i--;
						alreadyExist = true;
					}
					i++;
				}

				OutputStream pubOut = new FileOutputStream("pub.asc");
				pubOut = new ArmoredOutputStream(pubOut);
				pubRings.encode(pubOut);
				pubOut.close();

				PublicKeys.refreshPublicKeysPanel();
				
				JOptionPane.showMessageDialog(null, "Successfully imported " + i + " public keys!"
						+ (alreadyExist ? " Some public keys already exist." : ""));
			} catch (PGPException e) {
				JOptionPane.showMessageDialog(null, "This file must contain public keys!");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	public static void refreshPublicKeysPanel() {
		Main.pubKeyRingPanel.removeAll();
		listPublicKeys(Main.pubKeyRingPanel);
	}
}
