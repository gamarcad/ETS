use protego::{ExtProof, random_z_star_p};
use protego::mercurial_signatures::*;
use protego::scds::*;
use protego::protocol::{Credential, MockProtocol, Omega};
use protego::{G1Affine, G2Projective, Scalar};
use blake3::{Hasher, Hash};

const PKSIZE : usize = 7;




pub(crate) struct JudgeKey {
    attributes : Vec<Scalar>,
    mock : MockProtocol,
    nym : Scalar,
    org_keys: Vec<[G2Projective; PKSIZE]> ,
    tx : Hash,
    pi : ExtProof,
    rho : Scalar,
    gamma : Scalar
}

impl JudgeKey {
    pub fn new()  -> Self {

        let mut attributes = vec![];
        for _ in 0..1 {
            attributes.push(random_z_star_p());
        }

        let nym : Scalar = random_z_star_p();
        let NYM = vec![nym.clone()];
        let RNYM = vec![random_z_star_p()];

        //Create a set of organisation keys, in this test we consider the signing organisation to be
        //the third of the set
        let n = 1; //Size of confidentiality set of organisation keys
        let mut org_keys: Vec<[G2Projective; PKSIZE]> = Vec::with_capacity(n);
        unsafe {
            org_keys.set_len(n);
        }

        let mut mock_organisation_secret_key: Vec<Scalar> = vec![];
        let mut mock_organisation_public_key: Vec<G2Projective> = vec![];
        let signer = MercurialSignatureScheme::new(7);
        for i in 0..n {
            let pki = signer.key_gen();
            //The mock protocol organisation key belong to the set of organisation keys
            if i == 0 {
                mock_organisation_secret_key = pki.0.clone();
                mock_organisation_public_key = pki.1.clone();
            }

            for j in 0..PKSIZE {
                org_keys[i][j] = pki.1[j];
            }
        }

        //Fake transaction hash
        let mut hasher = Hasher::new();
        hasher.update(&G1Affine::generator().to_compressed());
        let tx = hasher.finalize();

        //Full initialisation of the party that plays all the roles in the transaction
        let mut mock = MockProtocol::full_setup(
            2,
            2,
            &NYM,
            RNYM,
            &mock_organisation_secret_key,
            &mock_organisation_public_key,
        );

        let index = 0;
        let mut x1: [G2Projective; PKSIZE] = Default::default();
        let mut x2: [G2Projective; PKSIZE] = Default::default();
        let rho = random_z_star_p();
        let gamma = random_z_star_p();
        for i in 0..PKSIZE {
            x1[i] = org_keys[index][i] * rho;
            x2[i] = org_keys[index][i] * gamma;
        }
        let pi = mock
            .signer_hiding
            .PPro(&org_keys, &x1, &x2, rho, gamma, n, index);

        Self {
            attributes,
            mock,
            org_keys,
            nym,
            tx,
            pi,
            rho,
            gamma
        }
    }


    pub fn obtain(&self) -> Credential {
        let cred = self.mock.obtain(&self.attributes, &self.nym);
        cred
    }

    pub fn show(&mut self, cred: &Credential) -> Omega {
        let (mut omega, _) = self.mock.show(
            cred.clone(),
            &self.attributes,
            &self.attributes,
            &vec![],
            &mut self.org_keys,
            &self.pi,
            &self.tx,
            &self.nym,
            &self.rho,
            &self.gamma,
            true,
            false,
            true,
        );

        omega
    }

    pub fn verify(&mut self, mut omega: Omega) -> bool {
        let is_verified = self.mock.verify(
            &self.attributes,
            &vec![],
            &self.org_keys,
            &self.tx,
            &mut omega
        );
        is_verified
    }
}