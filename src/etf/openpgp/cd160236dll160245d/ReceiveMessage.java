package etf.openpgp.cd160236dll160245d;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Iterator;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

public class ReceiveMessage {
	
	public static void receive() {
		JFrame sourceFrame = new JFrame();

		JFileChooser sourceFileChooser = new JFileChooser();
		sourceFileChooser.setDialogTitle("Choose a file");

		int userSelectionSrc = sourceFileChooser.showSaveDialog(sourceFrame);

		if (userSelectionSrc == JFileChooser.APPROVE_OPTION) {
			File sourceFile = sourceFileChooser.getSelectedFile();
			
			JFrame destFrame = new JFrame();

			JFileChooser destFileChooser = new JFileChooser();
			destFileChooser.setDialogTitle("Choose a destination folder");

			int userSelectionDest = destFileChooser.showSaveDialog(destFrame);

			if (userSelectionDest == JFileChooser.APPROVE_OPTION) {
				File destinationFile = destFileChooser.getSelectedFile();
				try {
					decryptVerify(sourceFile.getAbsolutePath(), destinationFile.getAbsolutePath());
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	private static boolean verifyFile(String filePathTo, Object passedObject, JcaPGPObjectFactory pgpFact) throws Exception {

		PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) passedObject;

		PGPOnePassSignature ops = p1.get(0);

		PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

		InputStream dIn = p2.getInputStream();

		int ch;
		PGPPublicKeyRingCollection pgpRingCollection = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(new FileInputStream("pub.asc")), new JcaKeyFingerprintCalculator());
		
		PGPPublicKey key = pgpRingCollection.getPublicKey(ops.getKeyID());

		if (key == null) {
			JOptionPane.showMessageDialog(null,
					"Message can not be verified! Public key not found in your Public Key Ring!");
			return false;
		}
		
		FileOutputStream out = new FileOutputStream(filePathTo);

		ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

		while ((ch = dIn.read()) >= 0) {
			ops.update((byte) ch);
			out.write(ch);
		}

		PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

		boolean verified = ops.verify(p3.get(0));
		if (verified) {
			byte[] rawUserIDs = key.getRawUserIDs().next();
			JOptionPane.showMessageDialog(null, "Message was sent by " + new String(rawUserIDs));
			
			System.out.println("signature verified.");
		} else {
			System.out.println("signature verification failed.");
		}
		out.close();
		return verified;
	}
	
	/*public static boolean verify(InputStream signedData, InputStream signature) {
	    try {
	        signature = PGPUtil.getDecoderStream(signature);
	        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(signature);
	        PGPSignature sig = ((PGPSignatureList) pgpFact.nextObject()).get(0);
	        PGPPublicKeyRingCollection pgpRingCollection = new PGPPublicKeyRingCollection(
					PGPUtil.getDecoderStream(new FileInputStream("pub.asc")), new JcaKeyFingerprintCalculator());
	        PGPPublicKey key = pgpRingCollection.getPublicKey(sig.getKeyID());
	        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
	        byte[] buff = new byte[1024];
	        int read = 0;
	        while ((read = signedData.read(buff)) != -1) {
	            sig.update(buff, 0, read);
	        }
	        signedData.close();
	        return sig.verify();
	    }
	    catch (Exception ex) {
	        return false;
	    }
	}*/

	@SuppressWarnings({ "resource", "rawtypes" })
	public static void decryptVerify(String filePathFrom, String filePathTo) throws Exception {

		InputStream in = new ByteArrayInputStream(SendMessage.readMessageFromFile(new File(filePathFrom)));

		in = PGPUtil.getDecoderStream(in);

		JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
		Object o = pgpFact.nextObject();
		boolean allOK = true;

		if (o instanceof PGPEncryptedDataList) {
			PGPEncryptedDataList enc = (PGPEncryptedDataList) o;

			//
			// find the secret key
			//
			Iterator it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;
			PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
					PGPUtil.getDecoderStream(new FileInputStream("secret.asc")), new JcaKeyFingerprintCalculator());

			while (sKey == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();

				PGPSecretKey pgpSecKey = pgpSec.getSecretKey(pbe.getKeyID());

				if (pgpSecKey == null) {
					continue;
				}

				try {
					sKey = SecretKeys.extractPrivateKey(pgpSecKey, SecretKeys.enterPassPhraseDialog().toCharArray());
				} catch (IncorrectPassPhraseException e) {
					JOptionPane.showMessageDialog(null, "Incorrect passphrase!");
					return;
				}
			}

			if (sKey == null) {
				JOptionPane.showMessageDialog(null, "Secret key for message not found.");
				return;
			}
			
			InputStream clear = pbe
					.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
			
			pgpFact = new JcaPGPObjectFactory(clear);
			o = pgpFact.nextObject();
		}
		
		if (o instanceof PGPCompressedData) {
			PGPCompressedData cData = (PGPCompressedData) o;
			
			pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
			
			o = pgpFact.nextObject();
		}
		
		if (o instanceof PGPOnePassSignatureList) {
			
			allOK = verifyFile(filePathTo, o, pgpFact);
			
		} else if (o instanceof PGPLiteralData) {
			PGPLiteralData ld = (PGPLiteralData) o;

			InputStream dIn = ld.getInputStream();
			FileOutputStream out = new FileOutputStream(filePathTo);
			int ch;
			while ((ch = dIn.read()) >= 0) {
				out.write(ch);
			}
			out.close();
		} /*else if (o instanceof PGPSignatureList) {
			allOK = verify(new FileInputStream("C:\\Users\\Lazar\\Desktop\\input.txt"), new FileInputStream("C:\\Users\\Lazar\\Desktop\\input.txt.sig"));
			System.out.println(allOK);
		}*/
		
		if (allOK) {
			JOptionPane.showMessageDialog(null, "Message successfully received!");
		}

		in.close();
	}
}
