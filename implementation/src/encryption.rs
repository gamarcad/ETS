use std::collections::HashMap;
use rust_elgamal::{Ciphertext, CompressedRistretto, DecryptionKey, EncryptionKey, GENERATOR_POINT, GENERATOR_TABLE, RistrettoPoint, Scalar};
use rand::{Rng, thread_rng};
use crate::randomize::Randomize;


pub struct PointMapper {
    map: HashMap<[u8;32], u8>
}



impl PointMapper {
    pub(crate) fn new() -> Self {
        let mut map : HashMap<[u8;32], u8> = HashMap::new();

        for i in 0..=255u8 {
            let scalar = Scalar::from( i as u64 );
            let point = scalar * &GENERATOR_POINT;
            let compressed_point = point.compress();
            map.insert( compressed_point.to_bytes(), i );
        }

        Self {
            map,
        }
    }

    pub(crate) fn get( &self, point : &RistrettoPoint ) -> u8 {
        let compressed = point.compress();
        self.get_compressed(&compressed)
    }

    pub(crate) fn get_compressed( &self, compressed_point : &CompressedRistretto ) -> u8 {
        *self.map.get( &compressed_point.0 ).unwrap()
    }
}

pub struct  EncryptionKeyPair {
    encryption_key : EncryptionKey,
    decryption_key : DecryptionKey,
}


impl EncryptionKeyPair {
    pub(crate) fn new() -> EncryptionKeyPair {
        let decryption_key = DecryptionKey::new(&mut thread_rng());
        let encryption_key = *decryption_key.encryption_key();
        EncryptionKeyPair {
            encryption_key,
            decryption_key,
        }
    }

    pub(crate) fn public_key_to_bytes(&self) -> [u8; 32] {
        self.encryption_key.as_ref().compress().0
    }

    pub(crate) fn encrypt( &self, m : &Vec<u8> ) -> Vec<Ciphertext> {
        let mut ciphertext : Vec<Ciphertext> = vec!();
        let rang = &mut thread_rng();
        for m_i in m {
            let c_i = self.encryption_key.encrypt(
                &Scalar::from(*m_i as u32) * &GENERATOR_TABLE,
                rang,
            );
            ciphertext.push(c_i);
        }
        ciphertext
    }

    pub(crate) fn decrypt( &self, mapper : &PointMapper, ciphertext : &Vec<Ciphertext>  ) ->
                                                                                         Vec<u8> {
        let mut plaintext : Vec<u8> = vec!();
        for c_i in ciphertext {
            let m_i = self.decryption_key.decrypt(
                *c_i
            );
            plaintext.push(
                mapper.get(&m_i)
            )
        }
        plaintext
    }
}

impl Randomize for EncryptionKeyPair {
    fn randomize<'a>(&self) -> EncryptionKeyPair {
        let value  = rand::thread_rng().gen::<u128>();
        let random = Scalar::from(value);
        let randomized_decryption_key = DecryptionKey::from(random);
        let randomized_encryption_key = *randomized_decryption_key.encryption_key();
        EncryptionKeyPair {
            encryption_key: randomized_encryption_key,
            decryption_key: randomized_decryption_key,
        }
    }
}
