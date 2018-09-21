package com.amirkhawaja.ecdhe.service;

import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

@NoArgsConstructor
@Service
public class KeyService {

	/**
	 * Generate an ephemeral private and public key pair.
	 *
	 * @return Key pair.
	 * @throws NoSuchAlgorithmException
	 */
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(256); // Set p=256

		return generator.generateKeyPair();
	}

	/**
	 * Derive a shared secret using one party's public key and your secret key.
	 *
	 * @param otherPublicKey PKCS#8 public certificate
	 * @param yourPrivateKey PKCS#8 private key
	 * @return The shared secret.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 */
	public byte[] deriveSharedSecret(byte[] otherPublicKey, ECPrivateKey yourPrivateKey) throws
			NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
		final KeyFactory ec = KeyFactory.getInstance("EC");
		final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(otherPublicKey);
		final PublicKey publicKey = ec.generatePublic(keySpec);
		KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
		ecdh.init(yourPrivateKey);
		ecdh.doPhase(publicKey, true);

		return ecdh.generateSecret();
	}

}
