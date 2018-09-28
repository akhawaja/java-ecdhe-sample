package com.amirkhawaja.ecdhe;

import com.amirkhawaja.ecdhe.service.KeyService;
import com.amirkhawaja.ecdhe.service.SymmetricEncryptionService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Component
@Slf4j
public class EcdhCommandLineRunner implements CommandLineRunner {

	private KeyService keyService;
	private SymmetricEncryptionService encryptionService;

	@Autowired
	public EcdhCommandLineRunner(SymmetricEncryptionService encryptionService, KeyService keyService) {
		this.encryptionService = encryptionService;
		this.keyService = keyService;
	}

	@Override
	public void run(String... args) throws Exception {
		// Generate an ephemeral PKCS8 key pair
		final KeyPair aliceKeyPair = keyService.generateKeyPair();
		final KeyPair bobKeyPair = keyService.generateKeyPair();

		// Extract the public and private keys
		final ECPublicKey alicePub = (ECPublicKey) aliceKeyPair.getPublic();
		final ECPrivateKey alicePriv = (ECPrivateKey) aliceKeyPair.getPrivate();
		final ECPublicKey bobPub = (ECPublicKey) bobKeyPair.getPublic();
		final ECPrivateKey bobPriv = (ECPrivateKey) bobKeyPair.getPrivate();

		// Derive a shared secret using the generated keys
		final byte[] secret1 = keyService.deriveSharedSecret(bobPub.getEncoded(), alicePriv);
		final byte[] secret2 = keyService.deriveSharedSecret(alicePub.getEncoded(), bobPriv);

		// Print the secrets
		log.info("Do both the secrets match? {}", Hex.encodeHexString(secret1).equals(Hex.encodeHexString(secret2)));
		log.info("Alice's secret: {}", Hex.encodeHexString(secret1));
		log.info("Bob's secret: {}", Hex.encodeHexString(secret2));

		// Encrypt some text.
		final byte[] content = encryptionService.encrypt(secret1, "This is a test".getBytes(StandardCharsets.UTF_8));
		log.info("Encrypted: {}", new String(content));
		log.info("Decrypted: {}", new String(encryptionService.decrypt(secret2, content)));
	}

}
