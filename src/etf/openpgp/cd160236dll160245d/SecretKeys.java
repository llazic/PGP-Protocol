package etf.openpgp.cd160236dll160245d;

import java.awt.BorderLayout;
import java.awt.Dialog.ModalityType;
import java.awt.GridLayout;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Iterator;

import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class SecretKeys {

	@SuppressWarnings("rawtypes")
	public static void listSecretKeys(JPanel panel) {
		String[] columnNames = { "Name", "EMail", "Timestamp", "KeyID" };

		try {
			File secretFile = new File("secret.asc");
			secretFile.createNewFile(); // if file already exists will do nothing 
			
			PGPSecretKeyRingCollection secretRings = new PGPSecretKeyRingCollection(
					PGPUtil.getDecoderStream(new FileInputStream("secret.asc")), new JcaKeyFingerprintCalculator());

			Iterator rIt = secretRings.getKeyRings();
			Object[][] data = new Object[secretRings.size()][4];
			int i = 0;

			while (rIt.hasNext()) {
				PGPSecretKeyRing pgpSecret = (PGPSecretKeyRing) rIt.next();

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

	public static boolean generateNewKeyPairDialog() {
		String[] DSAItems = { "1024", "2048" };
		JComboBox<String> DSACombo = new JComboBox<>(DSAItems);
		String[] ElGamalItems = { "1024", "2048", "4096" };
		JComboBox<String> ElGamalCombo = new JComboBox<>(ElGamalItems);
		JTextField nameTextField = new JTextField();
		JTextField emailTextField = new JTextField();
		JPanel panel = new JPanel(new GridLayout(0, 1));
		panel.add(new JLabel("Name:"));
		panel.add(nameTextField);
		panel.add(new JLabel("EMail:"));
		panel.add(emailTextField);
		panel.add(new JLabel("Choose DSA key length:"));
		panel.add(DSACombo);
		panel.add(new JLabel("Choose ElGamal key length:"));
		panel.add(ElGamalCombo);

		int result = JOptionPane.showConfirmDialog(null, panel, "New key pair", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.PLAIN_MESSAGE);

		if (result == JOptionPane.OK_OPTION) {
			String name = nameTextField.getText();
			String email = emailTextField.getText();
			if (name != null && "".equals(name) == false && email != null && "".equals(email) == false) {
				String userID = name + " <" + email + ">";
				int DSAKeyLength = Integer.parseInt((String) (DSACombo.getSelectedItem()));
				int ElGamalKeyLength = Integer.parseInt((String) (ElGamalCombo.getSelectedItem()));
				// System.out.println(userID + " " + DSAKeyLength + " " + ElGamalKeyLength);

				String passPhrase = SecretKeys.enterPassPhraseDialog();
				if (passPhrase != null) {
					try {
						JOptionPane pane = new JOptionPane("Message", JOptionPane.INFORMATION_MESSAGE);
						JDialog dialog = pane.createDialog("Generating keys...");
						dialog.setModalityType(ModalityType.MODELESS);
						dialog.setVisible(true);

						DSAElGamalKeyRingGenerator.generateKeyPair(userID, passPhrase, DSAKeyLength, ElGamalKeyLength);
						dialog.setVisible(false);

						JOptionPane.showMessageDialog(null, "Keys generated!");
						SecretKeys.refreshSecretKeysPanel();
						return true;
					} catch (Exception e) {
						e.printStackTrace();
					}
				} else {
					return false;
				}
			} else {
				return false;
			}
		} else {
			System.out.println("Cancelled");
			return true;
		}
		return false;
	}

	public static String enterPassPhraseDialog() {
		JTextField passPhraseTextField = new JTextField();
		JPanel panel = new JPanel(new GridLayout(0, 1));
		panel.add(new JLabel("PassPhrase:"));
		panel.add(passPhraseTextField);
		int result = JOptionPane.showConfirmDialog(null, panel, "Enter PassPhrase", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.PLAIN_MESSAGE);
		if (result == JOptionPane.OK_OPTION) {
			String passPhrase = passPhraseTextField.getText();
			if (passPhrase == null || "".equals(passPhrase))
				return null;
			else
				return passPhrase;
		} else {
			return null;
		}
	}

	public static void refreshSecretKeysPanel() {
		Main.secretKeyRingPanel.removeAll();
		listSecretKeys(Main.secretKeyRingPanel);
	}

	@SuppressWarnings("rawtypes")
	public static void removeKeyPair() {
		PGPSecretKeyRingCollection secretRings;
		try {
			secretRings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(new FileInputStream("secret.asc")),
					new JcaKeyFingerprintCalculator());

			Iterator rIt = secretRings.getKeyRings();
			// Object[][] data = new Object[secretRings.size()][4];
			PGPSecretKeyRing[] secretKeyRingArray = new PGPSecretKeyRing[secretRings.size()];
			String[] secretKeyRingStrings = new String[secretRings.size()];
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

			JComboBox<String> secretKeysCombo = new JComboBox<>(secretKeyRingStrings);
			JPanel panel = new JPanel(new GridLayout(0, 1));
			panel.add(new JLabel("Choose key to remove:"));
			panel.add(secretKeysCombo);

			int result = JOptionPane.showConfirmDialog(null, panel, "Remove", JOptionPane.OK_CANCEL_OPTION,
					JOptionPane.PLAIN_MESSAGE);

			if (result == JOptionPane.OK_OPTION) {
				int selectedIndex = secretKeysCombo.getSelectedIndex();
				PGPSecretKeyRing selectedKeyRing = secretKeyRingArray[selectedIndex];

				String passPhrase = SecretKeys.enterPassPhraseDialog();

				try {
					try {
						SecretKeys.extractPrivateKey(selectedKeyRing.getSecretKey(), passPhrase.toCharArray());
					} catch (NullPointerException e) {
						//nije
					}

					secretRings = PGPSecretKeyRingCollection.removeSecretKeyRing(secretRings, selectedKeyRing);

					OutputStream secretOut = new FileOutputStream("secret.asc");
					secretOut = new ArmoredOutputStream(secretOut);
					secretRings.encode(secretOut);
					secretOut.close();

					SecretKeys.refreshSecretKeysPanel();

					JOptionPane.showMessageDialog(null, "Key pair removed!");

				} catch (IncorrectPassPhraseException e) {
					JOptionPane.showMessageDialog(null, "Incorrect passphrase!");
				} catch (NullPointerException e) {
					//vrv je kliknuto na cancel prilikom unosenja lozinke
					e.printStackTrace();
				}

			} else {
				System.out.println("Cancelled!");
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}

	@SuppressWarnings("rawtypes")
	public static void exportKeyPair() {
		PGPSecretKeyRingCollection secretRings;
		try {
			secretRings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(new FileInputStream("secret.asc")),
					new JcaKeyFingerprintCalculator());

			Iterator rIt = secretRings.getKeyRings();
			// Object[][] data = new Object[secretRings.size()][4];
			PGPSecretKeyRing[] secretKeyRingArray = new PGPSecretKeyRing[secretRings.size()];
			String[] secretKeyRingStrings = new String[secretRings.size()];
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

			JComboBox<String> secretKeysCombo = new JComboBox<>(secretKeyRingStrings);
			JPanel panel = new JPanel(new GridLayout(0, 1));
			panel.add(new JLabel("Choose key pair to export:"));
			panel.add(secretKeysCombo);

			int result = JOptionPane.showConfirmDialog(null, panel, "Export", JOptionPane.OK_CANCEL_OPTION,
					JOptionPane.PLAIN_MESSAGE);

			if (result == JOptionPane.OK_OPTION) {
				int selectedIndex = secretKeysCombo.getSelectedIndex();
				PGPSecretKeyRing selectedKeyRing = secretKeyRingArray[selectedIndex];

				String passPhrase = SecretKeys.enterPassPhraseDialog();

				try {
					SecretKeys.extractPrivateKey(selectedKeyRing.getSecretKey(), passPhrase.toCharArray());

					JFrame parentFrame = new JFrame();

					JFileChooser fileChooser = new JFileChooser();
					fileChooser.setDialogTitle("Specify a file to save");

					int userSelection = fileChooser.showSaveDialog(parentFrame);

					if (userSelection == JFileChooser.APPROVE_OPTION) {
						File fileToSave = fileChooser.getSelectedFile();
						System.out.println("Save as file: " + fileToSave.getAbsolutePath());

						OutputStream secretOut = new FileOutputStream(fileToSave.getAbsolutePath() + ".asc");
						secretOut = new ArmoredOutputStream(secretOut);
						selectedKeyRing.encode(secretOut);
						secretOut.close();

						JOptionPane.showMessageDialog(null, "Key pair successfully exported!");
					}
				} catch (IncorrectPassPhraseException e) {
					JOptionPane.showMessageDialog(null, "Incorrect passphrase!");
				}

			} else {
				System.out.println("Cancelled!");
			}
		} catch (IOException | PGPException e1) {
			e1.printStackTrace();
		}
	}

	// zovemo da proverimo da li je ok passPhrase
	// ne znamo da li moze da se koristi za dekripciju
	public static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase)
			throws IncorrectPassPhraseException {
		PGPPrivateKey privateKey = null;
		BcPGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();
		BcPBESecretKeyDecryptorBuilder secretKeyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(
				calculatorProvider);
		PBESecretKeyDecryptor pBESecretKeyDecryptor = secretKeyDecryptorBuilder.build(passPhrase);

		try {
			privateKey = pgpSecKey.extractPrivateKey(pBESecretKeyDecryptor);
		} catch (PGPException e) {
			throw new IncorrectPassPhraseException();
		}

		return privateKey;
	}

	@SuppressWarnings("rawtypes")
	public static void importKeyPair() {
		JFrame parentFrame = new JFrame();

		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Specify a file to import");

		int userSelection = fileChooser.showSaveDialog(parentFrame);

		if (userSelection == JFileChooser.APPROVE_OPTION) {
			File fileToOpen = fileChooser.getSelectedFile();

			try {
				PGPSecretKeyRingCollection secretRingsToImport = new PGPSecretKeyRingCollection(
						PGPUtil.getDecoderStream(new FileInputStream(fileToOpen.getAbsolutePath())),
						new JcaKeyFingerprintCalculator());

				PGPSecretKeyRingCollection secretRings = new PGPSecretKeyRingCollection(
						PGPUtil.getDecoderStream(new FileInputStream("secret.asc")), new JcaKeyFingerprintCalculator());

				Iterator rIt = secretRingsToImport.getKeyRings();
				int i = 0;
				boolean alreadyExist = false;
				while (rIt.hasNext()) {
					PGPSecretKeyRing pgpSecret = (PGPSecretKeyRing) rIt.next();

					try {
						pgpSecret.getPublicKey();
					} catch (Exception e) {
						e.printStackTrace();
						continue;
					}
					try {
						secretRings = PGPSecretKeyRingCollection.addSecretKeyRing(secretRings, pgpSecret);
					} catch (IllegalArgumentException e) {
						i--;
						alreadyExist = true;
					}
					i++;
				}

				OutputStream secretOut = new FileOutputStream("secret.asc");
				secretOut = new ArmoredOutputStream(secretOut);
				secretRings.encode(secretOut);
				secretOut.close();

				SecretKeys.refreshSecretKeysPanel();
				
				JOptionPane.showMessageDialog(null, "Successfully imported " + i + " key pairs!"
						+ (alreadyExist ? " Some key pairs already exist." : ""));
			} catch (PGPException e) {
				JOptionPane.showMessageDialog(null, "This file must contain secret key pair(s)!");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
