package etf.openpgp.cd160236dll160245d;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Iterator;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class SendMessage {
	public static final int TRIPLE_DES = 0;
	public static final int IDEA = 1;

	@SuppressWarnings("rawtypes")
	public static void send() {

		JFrame parentFrame = new JFrame();

		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Choose a file to send");

		int userSelection = fileChooser.showSaveDialog(parentFrame);

		if (userSelection == JFileChooser.APPROVE_OPTION) {
			File fileToOpen = fileChooser.getSelectedFile();

			JPanel panel = new JPanel(new GridLayout(0, 1));

			// dohvatamo kljuceve iz secret key ringa
			PGPSecretKeyRingCollection secretRings;
			PGPSecretKeyRing[] secretKeyRingArray = null;
			String[] secretKeyRingStrings = null;
			try {
				secretRings = new PGPSecretKeyRingCollection(
						PGPUtil.getDecoderStream(new FileInputStream("secret.asc")), new JcaKeyFingerprintCalculator());

				Iterator rIt = secretRings.getKeyRings();
				// Object[][] data = new Object[secretRings.size()][4];
				secretKeyRingArray = new PGPSecretKeyRing[secretRings.size()];
				secretKeyRingStrings = new String[secretRings.size()];
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
			} catch (Exception e1) {
				e1.printStackTrace();
			}
			JComboBox<String> authenticationCombo = new JComboBox<>(secretKeyRingStrings);
			JLabel labelAuthentication = new JLabel("Choose key for authentication:");
			authenticationCombo.setEnabled(false);
			labelAuthentication.setEnabled(false);

			JCheckBox authenticationCheckBox = new JCheckBox("Enable authentication");
			authenticationCheckBox.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					labelAuthentication.setEnabled(!labelAuthentication.isEnabled());
					authenticationCombo.setEnabled(!authenticationCombo.isEnabled());
				}
			});

			// dohvatamo kljuceve iz public key ringa
			PGPPublicKeyRingCollection pubRings;
			PGPPublicKeyRing[] pubKeyRingArray = null;
			String[] pubKeyRingStrings = null;
			try {
				pubRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(new FileInputStream("pub.asc")),
						new JcaKeyFingerprintCalculator());

				Iterator rIt = pubRings.getKeyRings();
				// Object[][] data = new Object[secretRings.size()][4];
				pubKeyRingArray = new PGPPublicKeyRing[pubRings.size()];
				pubKeyRingStrings = new String[pubRings.size()];
				int i = 0;

				while (rIt.hasNext()) {
					PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();
					pubKeyRingArray[i] = pgpPub;

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

					pubKeyRingStrings[i] = array[0] + ", " + array[1].substring(1, array[1].length() - 1) + ", "
							+ Long.toHexString(pgpKey.getKeyID());

					i++;
				}
			} catch (Exception e1) {
				e1.printStackTrace();
			}
			JLabel labelRecepient = new JLabel("Choose recepient:");
			JList<String> recepientJList = new JList<>(pubKeyRingStrings);

			JLabel labelEncryption = new JLabel("Choose encryption algorithm:");
			String[] symmetricAlgorithms = { "IDEA", "3DES" };
			JComboBox<String> symetricAlgorithmCombo = new JComboBox<>(symmetricAlgorithms);

			recepientJList.setEnabled(false);
			symetricAlgorithmCombo.setEnabled(false);
			labelEncryption.setEnabled(false);
			labelRecepient.setEnabled(false);

			JCheckBox encryptionCheckBox = new JCheckBox("Enable encryption");
			encryptionCheckBox.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					labelEncryption.setEnabled(!labelEncryption.isEnabled());
					recepientJList.setEnabled(!recepientJList.isEnabled());
					symetricAlgorithmCombo.setEnabled(!symetricAlgorithmCombo.isEnabled());
					labelRecepient.setEnabled(!labelRecepient.isEnabled());
				}
			});

			panel.add(authenticationCheckBox);
			panel.add(labelAuthentication);
			panel.add(authenticationCombo);

			panel.add(encryptionCheckBox);
			panel.add(labelEncryption);
			panel.add(symetricAlgorithmCombo);
			panel.add(labelRecepient);
			panel.add(recepientJList);

			JCheckBox compressionCheckBox = new JCheckBox("Enable compression [ZIP]");
			panel.add(compressionCheckBox);

			JCheckBox conversionCheckBox = new JCheckBox("Enable conversion");
			panel.add(conversionCheckBox);

			int result = JOptionPane.showConfirmDialog(null, panel, "Send Message", JOptionPane.OK_CANCEL_OPTION,
					JOptionPane.PLAIN_MESSAGE);

			/*********** POCETAK OBRADE PORUKE ***********/
			if (result == JOptionPane.OK_OPTION) {
				if(recepientJList.getSelectedIndices().length == 0 && encryptionCheckBox.isSelected()) {
					JOptionPane.showMessageDialog(null, "No public key selected!");
					return;
				}
				
				byte[] modifiedMessage = readMessageFromFile(fileToOpen);

				if (modifiedMessage != null) {

					JFrame destFrame = new JFrame();

					JFileChooser destFileChooser = new JFileChooser();
					destFileChooser.setDialogTitle("Choose a destination folder");

					int userSelectionDest = destFileChooser.showSaveDialog(destFrame);

					if (userSelectionDest == JFileChooser.APPROVE_OPTION) {
						File destinationFile = destFileChooser.getSelectedFile();
						OutputStream messageOut = null;
						try {
							messageOut = new FileOutputStream(destinationFile.getAbsolutePath());
							messageOut.write(modifiedMessage);
							messageOut.close();
						} catch (FileNotFoundException e2) {
							e2.printStackTrace();
						} catch (IOException e1) {
							e1.printStackTrace();
						}

						/*********** AUTENTIKACIJA ***********/
						if (authenticationCheckBox.isSelected()) {
							int selectedIndex = authenticationCombo.getSelectedIndex();
							PGPSecretKeyRing selectedKeyRing = secretKeyRingArray[selectedIndex];

							try {
								ByteArrayOutputStream modifiedMessageOutputStream = new ByteArrayOutputStream();
								
								signFile(destinationFile.getAbsolutePath(), selectedKeyRing.getSecretKey(),
										modifiedMessageOutputStream, SecretKeys.enterPassPhraseDialog().toCharArray(),
										compressionCheckBox.isSelected());
								modifiedMessage = modifiedMessageOutputStream.toByteArray();

								messageOut = new FileOutputStream(destinationFile.getAbsolutePath());
								messageOut.write(modifiedMessage);
								messageOut.close();

								messageOut = new FileOutputStream("samo_autentikacija");
								messageOut.write(modifiedMessage);
								messageOut.close();
							} catch (IncorrectPassPhraseException e) {
								JOptionPane.showMessageDialog(null, "Incorrect passphrase!");
								return;
							} catch (Exception e1) {
								e1.printStackTrace();
							}
						}
						
						
						/*********** KOMPRESIJA ***********/
						if (compressionCheckBox.isSelected() && authenticationCheckBox.isSelected() == false) {
							try {
								byte[] mess = compressFile(destinationFile.getAbsolutePath(),
										CompressionAlgorithmTags.ZIP);

								messageOut = new FileOutputStream(destinationFile.getAbsolutePath());
								messageOut.write(mess);
								messageOut.close();
							} catch (IOException e1) {
								e1.printStackTrace();
							}
						}
						
						/*********** Literal Data Packet dopuna ***********/
						if(authenticationCheckBox.isSelected() == false && compressionCheckBox.isSelected() == false) {
							try {
								byte[] bytes = readMessageFromFile(destinationFile);
								
								//messageOut = new FileOutputStream(destinationFile.getAbsolutePath());
								ByteArrayOutputStream bOut = new ByteArrayOutputStream();
								PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
								OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, destinationFile);
								lOut.write(bytes);
								lOut.close();
								
								bytes = bOut.toByteArray();
								
								messageOut = new FileOutputStream(destinationFile.getAbsolutePath());
								messageOut.write(bytes);
								messageOut.close();
							} catch (Exception e1) {
								e1.printStackTrace();
							}
						}
						
						/*********** ENKRIPCIJA ***********/
						if(encryptionCheckBox.isSelected()) {
							int selectedSymmetricAlgorithm = symetricAlgorithmCombo.getSelectedIndex();
							int[] selectedRecepientIndices = recepientJList.getSelectedIndices();
							
							
							
							PGPPublicKeyRing[] selectedPublicKeyRecepients = new PGPPublicKeyRing[selectedRecepientIndices.length];
							for(int i = 0; i < selectedRecepientIndices.length; i++) {
								selectedPublicKeyRecepients[i] = pubKeyRingArray[selectedRecepientIndices[i]];
								System.out.println(selectedRecepientIndices[i]);
							}
							
							try {
								ByteArrayOutputStream modifiedMessageOutputStream = new ByteArrayOutputStream();
								
								encryptFile(modifiedMessageOutputStream, destinationFile.getAbsolutePath(), 
										selectedPublicKeyRecepients, true, selectedSymmetricAlgorithm + 1);
								modifiedMessage = modifiedMessageOutputStream.toByteArray();
								
								messageOut = new FileOutputStream(destinationFile.getAbsolutePath());
								messageOut.write(modifiedMessage);
								messageOut.close();
								
							} catch (NoSuchProviderException e1) {
								e1.printStackTrace();
							} catch (IOException e1) {
								e1.printStackTrace();
							}
							
							
						}

						/*********** KONVERZIJA ***********/
						if (conversionCheckBox.isSelected()) {
							byte[] endMessage = readMessageFromFile(destinationFile);
							try {
								messageOut = new FileOutputStream(destinationFile.getAbsolutePath());
								messageOut = new ArmoredOutputStream(messageOut);
								messageOut.write(endMessage);
								messageOut.close();
							} catch (Exception e1) {
								e1.printStackTrace();
							}
						}
						
						JOptionPane.showMessageDialog(null, "Message successfully saved!");
					}
				}
			}
		}
	}

	public static byte[] readMessageFromFile(File file) {
		try {
			return Files.readAllBytes(file.toPath());
		} catch (IOException e) {
			e.printStackTrace();
		} 
		return null;
	}

	@SuppressWarnings("rawtypes")
	private static void signFile(String fileName, PGPSecretKey pgpSec, OutputStream out, char[] pass, boolean shouldZIP)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException,
			IncorrectPassPhraseException {
		

		PGPPrivateKey pgpPrivKey = SecretKeys.extractPrivateKey(pgpSec, pass);
		PGPSignatureGenerator sGen = new PGPSignatureGenerator(
				new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

		sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

		Iterator it = pgpSec.getPublicKey().getUserIDs();
		if (it.hasNext()) {
			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

			spGen.setSignerUserID(false, (String) it.next());
			sGen.setHashedSubpackets(spGen.generate());
		}

		BCPGOutputStream bOut = null;
		PGPCompressedDataGenerator cGen = null;
		if(shouldZIP) {
			cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
			bOut = new BCPGOutputStream(cGen.open(out));
		} else {
			bOut = new BCPGOutputStream(out);
		}

		
		//ovo je tekst pre poruke
		sGen.generateOnePassVersion(false).encode(bOut);

		File file = new File(fileName);
		PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
		OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
		FileInputStream fIn = new FileInputStream(file);
		int ch;
		
		//ovde se upisuje poruka
		while ((ch = fIn.read()) >= 0) {
			lOut.write(ch);
			sGen.update((byte) ch);
		}

		lGen.close();
		
		//ovde se upisuje tekst posle poruke
		sGen.generate().encode(bOut);
		
		if (shouldZIP) {
			cGen.close();
		}

		fIn.close();
	}
	
	private static byte[] compressFile(String fileName, int algorithm) throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
            new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

	private static void encryptFile(OutputStream out, String fileName, PGPPublicKeyRing[] encKeys, boolean withIntegrityCheck, int symmetricAlgorithm)
			throws IOException, NoSuchProviderException {

		try {
			byte[] bytes = SendMessage.readMessageFromFile(new File(fileName));
			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(symmetricAlgorithm).setWithIntegrityPacket(withIntegrityCheck)
							.setSecureRandom(new SecureRandom()).setProvider("BC"));

			for (PGPPublicKeyRing encKeyRing : encKeys) {
				Iterator<PGPPublicKey> i = encKeyRing.getPublicKeys();
				i.next();
				encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(i.next()).setProvider("BC"));
			}

			OutputStream cOut = encGen.open(out, bytes.length);

			cOut.write(bytes);
			cOut.close();
		} catch (PGPException e) {
			System.err.println(e);
			if (e.getUnderlyingException() != null) {
				e.getUnderlyingException().printStackTrace();
			}
		}
	}
}
