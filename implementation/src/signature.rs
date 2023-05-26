use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{Rng, thread_rng};
use crate::randomize::Randomize;

pub struct SignatureKeyPair {
    signing_key_bytes : [u8; 32],
    signing_key:  SigningKey,
    verification_key :  VerifyingKey,
}

impl SignatureKeyPair {
    pub(crate) fn new() -> SignatureKeyPair {
        // creates a random bytes arroy of length 64
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();

        // creates the signature key pair
        let signing_key = SigningKey::from(random_bytes);
        let verification_key = VerifyingKey::from(&signing_key);
        SignatureKeyPair {
            signing_key_bytes: random_bytes,
            signing_key,
            verification_key,
        }
    }

    pub(crate) fn public_key_to_bytes(&self) -> [u8; 32] {
        self.verification_key.to_bytes()
    }

    pub(crate) fn sign(&self, message : &[u8]) -> Signature{
        self.signing_key.sign(&message)
    }

    pub(crate) fn verify(&self, message : &[u8], signature : &Signature) -> bool{
        match self.verification_key.verify(&message, &signature) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

impl Randomize for SignatureKeyPair {
    fn randomize<'a>(&self) -> SignatureKeyPair {
        // generate a new random
        let mut rng = thread_rng();
        let random = rng.gen::<u8>();

        // multiply each signing key bytes with the random
        let mut randomized_signing_key_bytes: [u8; 32] = [0; 32];
        for i in 0..32 {
            let (res, _) =self.signing_key_bytes[i].overflowing_add(random);
            randomized_signing_key_bytes[i] = res;
        }

        let randomized_signing_key = SigningKey::from(randomized_signing_key_bytes);
        let randomized_verification_key = VerifyingKey::from(&randomized_signing_key);
        SignatureKeyPair {
            signing_key_bytes: randomized_signing_key_bytes,
            signing_key: randomized_signing_key,
            verification_key: randomized_verification_key,
        }
    }
}