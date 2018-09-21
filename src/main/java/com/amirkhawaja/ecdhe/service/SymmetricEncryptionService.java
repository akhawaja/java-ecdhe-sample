package com.amirkhawaja.ecdhe.service;

import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@NoArgsConstructor
@Service
public class SymmetricEncryptionService {

	private final static String ALGORITHM = "AES";

	public byte[] encrypt(byte[] secret, byte[] content) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		SecretKeySpec keySpec = new SecretKeySpec(secret, ALGORITHM);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);

		return cipher.doFinal(content);
	}

	public byte[] decrypt(byte[] secret, byte[] encryptedContent) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		SecretKeySpec keySpec = new SecretKeySpec(secret, ALGORITHM);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, keySpec);

		return cipher.doFinal(encryptedContent);
	}

}
