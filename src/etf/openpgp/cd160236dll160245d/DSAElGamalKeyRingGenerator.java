package etf.openpgp.cd160236dll160245d;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates a secret keyring containing a
 * DSA signing key and an El Gamal key for encryption.
 * <p>
 * usage: DSAElGamalKeyRingGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are
 * placed in the files pub.[asc|bpg] and secret.[asc|bpg].
 * <p>
 * <b>Note</b>: this example encrypts the secret key using AES_256, many PGP
 * products still do not support this, if you are having problems importing keys
 * try changing the algorithm id to PGPEncryptedData.CAST5. CAST5 is more widely
 * supported.
 */
public class DSAElGamalKeyRingGenerator {

	private static void exportKeyPair(KeyPair dsaKp, KeyPair elgKp, String identity, char[] passPhrase, String path)
			throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
		
		// if file already exists will do nothing 
		File secretFile = new File("secret.asc");
		secretFile.createNewFile(); // if file already exists will do nothing 
		
		// dodajemo
		PGPSecretKeyRingCollection secretRings = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(new FileInputStream("secret.asc")), new JcaKeyFingerprintCalculator());
		//

		PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
		PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
				identity, sha1Calc, null, null,
				new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC")
						.build(passPhrase));

		keyRingGen.addSubKey(elgKeyPair);
		
		OutputStream secretOut = new FileOutputStream(path);
		secretOut = new ArmoredOutputStream(secretOut);
		secretRings = PGPSecretKeyRingCollection.addSecretKeyRing(secretRings, keyRingGen.generateSecretKeyRing());
		secretRings.encode(secretOut);
		secretOut.close();
	}

	public static void generateKeyPair(String identity, String passPhrase, int DSAKeyLength, int ElGamalKeyLength)
			throws Exception {

		KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
		dsaKpg.initialize(DSAKeyLength);
		// this takes a while as the key generator has to generate some DSA params
		// before it generates the key.
		KeyPair dsaKp = dsaKpg.generateKeyPair();

		KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
		elgKpg.initialize(ElGamalKeyLength);
		KeyPair elgKp = elgKpg.generateKeyPair();

		exportKeyPair(dsaKp, elgKp, identity, passPhrase.toCharArray(), "secret.asc");
	}
}
