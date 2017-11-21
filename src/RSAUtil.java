import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;

//import com.jd.uwp.common.Constants;

/**
 * RSA tools. Provide encryption, decryption, key generation equivalence method.
 * Requires the bcprov-jdk16-140.jar package.
 * 
 */
public class RSAUtil {

	private static String RSAKeyStore = "RSAKey.txt";
	private static String RSAPrivateKey = "RSAPrivateKey.txt";
	private static String basePath = "/Users/MyIBM/Documents/java_workspace/RSAEncryption/";

	/**
	 * * Generate a key pair *
	 * 
	 * @return KeyPair *
	 * @throws EncryptException
	 */
	public static KeyPair generateKeyPair(String basePath) throws Exception {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA",
					new org.bouncycastle.jce.provider.BouncyCastleProvider());
			// Size
			final int KEY_SIZE = 1024;
			keyPairGen.initialize(KEY_SIZE, new SecureRandom());
			KeyPair keyPair = keyPairGen.generateKeyPair();
			saveKeyPair(keyPair, basePath);
			return keyPair;
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}

	/**
	 * Gets the key to
	 * 
	 * @return
	 * @throws Exception
	 */
	public static KeyPair getKeyPair(String basePath) throws Exception {
		FileInputStream fis = new FileInputStream(
				StringUtils.isNotBlank(basePath) ? (basePath + RSAKeyStore) : RSAKeyStore);
		ObjectInputStream oos = new ObjectInputStream(fis);
		KeyPair kp = (KeyPair) oos.readObject();
		oos.close();
		fis.close();
		return kp;
	}
	
	/**
	 * Gets the private key to
	 * 
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey(String basePath) throws Exception {
		FileInputStream fis = new FileInputStream(
				StringUtils.isNotBlank(basePath) ? (basePath + RSAPrivateKey) : RSAPrivateKey);
		ObjectInputStream oos = new ObjectInputStream(fis);
		PrivateKey pk = (PrivateKey) oos.readObject();
		oos.close();
		fis.close();
		return pk;
	}

	/**
	 * Store the key
	 * 
	 * @param kp
	 * @throws Exception
	 */
	public static void saveKeyPair(KeyPair kp, String basePath) throws Exception {
		FileOutputStream fos = new FileOutputStream(
				StringUtils.isNotBlank(basePath) ? (basePath + RSAKeyStore) : RSAKeyStore);
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		// Key generation
		oos.writeObject(kp);
		oos.close();
		fos.close();
	}
	
	/**
	 * Store the private key
	 * 
	 * @param pk
	 * @throws Exception
	 */
	public static void savePrivateKey(PrivateKey pk, String basePath) throws Exception {
		FileOutputStream fos = new FileOutputStream(
				StringUtils.isNotBlank(basePath) ? (basePath + RSAPrivateKey) : RSAPrivateKey);
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		// Key generation
		oos.writeObject(pk);
		oos.close();
		fos.close();
	}

	/**
	 * * Public *
	 * 
	 * @param modulus
	 * *
	 * @param publicExponent
	 * *
	 * @return RSAPublicKey *
	 * @throws Exception
	 */
	public static RSAPublicKey generateRSAPublicKey(byte[] modulus, byte[] publicExponent) throws Exception {
		KeyFactory keyFac = null;
		try {
			keyFac = KeyFactory.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ex.getMessage());
		}
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
		try {
			return (RSAPublicKey) keyFac.generatePublic(pubKeySpec);
		} catch (InvalidKeySpecException ex) {
			throw new Exception(ex.getMessage());
		}
	}

	/**
	 * * Generate key *
	 * 
	 * @param modulus
	 * *
	 * @param privateExponent
	 * *
	 * @return RSAPrivateKey *
	 * @throws Exception
	 */
	public static RSAPrivateKey generateRSAPrivateKey(byte[] modulus, byte[] privateExponent) throws Exception {
		KeyFactory keyFac = null;
		try {
			keyFac = KeyFactory.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ex.getMessage());
		}
		RSAPrivateKeySpec priKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
		try {
			return (RSAPrivateKey) keyFac.generatePrivate(priKeySpec);
		} catch (InvalidKeySpecException ex) {
			throw new Exception(ex.getMessage());
		}
	}

	/**
	 * * Encryption *
	 * 
	 * @param key
	 *            The encrypted key *
	 * @param data
	 *            The plaintext data to be encrypted *
	 * @Return encrypted data *
	 * @throws Exception
	 */
	public static byte[] encrypt(PublicKey pk, byte[] data) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, pk);
			// Get the encryption block size, such as: the pre encrypted data
			// for 128 byte, and key_size=1024
			int blockSize = cipher.getBlockSize();
			// The encryption block size is 127
			// byte,Encryption is 128 byte; therefore, a total of 2 encryption
			// block, the first 127
			// Byte second to 1 byte
			int outputSize = cipher.getOutputSize(data.length);// Obtain the
																// encrypted
																// block
																// encryption
																// block size
			int leavedSize = data.length % blockSize;
			int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;
			byte[] raw = new byte[outputSize * blocksSize];
			int i = 0;
			while (data.length - i * blockSize > 0) {
				if (data.length - i * blockSize > blockSize) {
					cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
				} else {
					cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);
				}
				i++;
			}
			return raw;
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}

	/**
	 * * Decrypt *
	 * 
	 * @param key
	 *            Decryption key *
	 * @param raw
	 *            Encrypted data *
	 * @Return decrypted plaintext *
	 * @throws Exception
	 */
	@SuppressWarnings("static-access")
	public static byte[] decrypt(PrivateKey pk, byte[] raw) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
			cipher.init(cipher.DECRYPT_MODE, pk);
			int blockSize = cipher.getBlockSize();
			ByteArrayOutputStream bout = new ByteArrayOutputStream(64);
			int j = 0;
			while (raw.length - j * blockSize > 0) {
				bout.write(cipher.doFinal(raw, j * blockSize, blockSize));
				j++;
			}
			return bout.toByteArray();
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}

	/**
	 * Decryption method paramStr ->Ciphertext basePath ->The path to the folder
	 * where RSAKey.txt
	 **/
	public static String decryptStr(String paramStr, String basePath) throws Exception {
		byte[] en_result = new BigInteger(paramStr, 16).toByteArray();
		//byte[] de_result = decrypt(getKeyPair(basePath).getPrivate(), en_result);
		byte[] de_result = decrypt(getPrivateKey(basePath), en_result);
		StringBuffer sb = new StringBuffer();
		sb.append(new String(de_result));
		// Returns the decrypted string
		return sb.toString();
	}
	
	public String getOriginalText(String text, int originalTextLength) throws Exception{
		byte[] decoded = Base64.decodeBase64(text.getBytes("utf-8"));
		String hexString = Hex.encodeHexString(decoded);
		String originalText = RSAUtil.decryptStr(hexString, RSAUtil.basePath);
		originalText = originalText.substring(originalText.length() - originalTextLength, originalText.length());
		return originalText;
	}
	
	public HashMap<String,String> getModExponent() throws Exception{
		KeyPair kp = RSAUtil.getKeyPair(RSAUtil.basePath);
		String pub = kp.getPublic().toString();
		String[] chunks = pub.split("\n");
		String modulous = chunks[1].split(":")[1];
		modulous = org.apache.commons.lang.StringUtils.replace(modulous, " ", "");
	    String exponent = chunks[2].split(":")[1];
	    exponent = org.apache.commons.lang.StringUtils.replace(exponent, " ", "");
	    HashMap<String,String> modExp = new HashMap<>();
	    modExp.put("mod", modulous);
	    modExp.put("exp", exponent);
		return modExp;
	}

	public static void main(String[] args) throws Exception {
		RSAUtil.savePrivateKey(getKeyPair(basePath).getPrivate(), basePath);
		//String value_ = "Y8T1eR9Qz35U4Vm8SNue7n6ZTEooYHRIzWcdUr2pBoFFmCZlEOvFOZOa3UqGX6XkDIf1IRqKczNPLHkunuUag0x4o+sqyIbDMN2H97E3erGdyNFpU5x10/5M+UGgXN/BkzQnezEv9I0uw2wbs6i9ZUt52UGHcw2QJOK7I/AbZwI=";
		
	}
}
