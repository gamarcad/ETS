
extern crate core;

mod signature;
mod randomize;
mod encryption;
mod audit;


use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};
use ed25519_dalek::Signature;
use rand::{Rng, thread_rng};
use crate::randomize::Randomize;
use crate::signature::SignatureKeyPair;
use sha2::{Sha256, Digest};
use rust_elgamal::Ciphertext;
use crate::encryption::{EncryptionKeyPair, PointMapper};
use std::option::Option;
use protego::protocol::{Credential, Omega};
use crate::audit::JudgeKey;


type IdeSpace = u8;
type IdpSpace = u8;
type RcSpace = Vec<u8>;
type Ticket =  (u8, u8, RcSpace, Signature);

const SEC_PAR_BITS : usize = 1024;
const SEC_PAR_BYTES : usize = SEC_PAR_BITS / 8;
const IDE: IdeSpace = 1;
const IDP: IdpSpace = 1;

//
// The shared state contains the tickets that are invalid.
//
// Note: The shared state voluntary contains a copy of every tickets and not only a reference
// since we want to measure the size of the shared state.
//
type Hash = Vec<u8>;

#[derive(Clone)]
struct  SharedState {
    state : HashMap<Hash, bool>
}


impl SharedState {
    fn new() -> Self {
        Self {
            state: HashMap::new()
        }
    }

    fn add_ticket(&mut self, hash  : Hash)  {
        self.state.insert(hash, true);
    }

    fn remove_ticket(&mut self, hash : &Hash)  {
        self.state.remove(hash);

    }

    fn contains_ticket(&self, hash : &Hash) -> bool {
        self.state.contains_key(hash)
    }


}




struct Timing {
    times : HashMap<String, HashMap<usize, Vec<u128>>>,
    buffers : HashMap<String, (u128, Option<Instant>)>,
}

impl Timing {
    pub(crate) fn new() -> Self {
        Self {
            times: HashMap::new(),
            buffers : HashMap::new(),
        }
    }

    pub(crate) fn start(&mut self, subject : String) {
        match self.buffers.get(&subject) {
            Some( (t, i) ) => {
                assert!(i.is_none());
                self.buffers.insert( String::from(subject), (t.clone(), Some(Instant::now())));
            },
            None => {
                self.buffers.insert( String::from(subject), (0, Some(Instant::now())));
            }
        }
    }

    pub(crate) fn pause(&mut self, subject : String) {
        let (buffer, instant) = self.buffers.get( &subject ).unwrap();
        self.buffers.insert( String::from(subject), (buffer + instant.unwrap().elapsed().as_millis(), None));
    }



    pub(crate) fn stop_all(&mut self, billet_id : usize) {


        for (subject, timing) in self.buffers.iter() {
            let subject = String::from(subject);

            // recover the execution time
            let (buffer, instant) = timing;
            let time = buffer + match instant {
                Some( t ) => t.elapsed().as_millis(),
                None => Duration::ZERO.as_millis()
            };

            // we insert the time in the right billet id
            match self.times.get_mut(&subject) {
                None => {
                    // create times
                    let mut times = Vec::new();
                    times.push(time);

                    let mut subject_times_n = HashMap::new();
                    subject_times_n.insert(billet_id, times);
                    self.times.insert(subject, subject_times_n);
                }
                Some(times_n) => {
                    match times_n.get_mut(&billet_id) {
                        None => {
                            let mut times = Vec::new();
                            times.push(time);
                            times_n.insert(billet_id, times );
                        },
                        Some(subject_times_n) => {
                            subject_times_n.push( time );
                        }
                    }
                }
            }
        }

        self.buffers.clear()
        
    }


 

    pub(crate) fn export_at( &self, filename : String, nb_iterations : usize, nb_billets : usize )
    {
       

        // generate 
        for (subject, many_times_by_billets) in self.times.iter() { 
            assert_eq!(many_times_by_billets.len(), nb_billets);


            // compute the mean 
            let mut mean_time_by_billets = Vec::<(usize, f64)>::new();
            for (billet, times) in many_times_by_billets.iter()  {
                let sum_times = times.clone().into_iter().reduce(|a, b| (a + b)).unwrap();
                let mean_time = sum_times as f64 / times.len() as f64;

                mean_time_by_billets.push( (*billet, mean_time) )
            }

            // sort by billet index
            mean_time_by_billets.sort_by(
                |(a, _), (b, _)| 
                a.partial_cmp(b).unwrap()
            );

            
            // export the result
            let mut file = File::create(format!("{}-{}.csv", filename, subject)).unwrap();
            file.write_all( format!("ticket, time\n").as_bytes() );
            for (billet, time) in mean_time_by_billets.iter() {
                file.write_all( format!("{}, {}\n", billet, time).as_bytes() );
            }

        }
    }

}

#[warn(unused_variables)]
fn bench_functions_with_state( enable_audit : bool  ) {
    // define the benchmarking setting

    #[cfg(feature = "single")]
    const NB_ITERATIONS: usize = 2;
    #[cfg(feature = "single")]
    const NB_BILLETS: usize = 10;

    let proto_name = {
        if enable_audit {
            String::from("spotlight")
        }  else {
            String::from("applause")
        }
    };

    #[cfg(not(feature = "single"))]
    const NB_ITERATIONS: usize = 200;
    #[cfg(not(feature = "single"))]
    const NB_BILLETS: usize = 1000;


    // evaluation parameter
    let mapper = PointMapper::new();

    // parameters definition
    let key_to_bytes =
        |
            signature_key : &SignatureKeyPair,
            encryption_key : &EncryptionKeyPair
        | -> Vec<u8> {
            let mut content_to_sign : Vec<u8> = Vec::new();
            content_to_sign.append(&mut signature_key.public_key_to_bytes().clone().to_vec());
            content_to_sign.append( &mut encryption_key.public_key_to_bytes().clone().to_vec() );
            content_to_sign
        };

    // create the judge key
    let mut judge_key = JudgeKey::new();

    // creating users key
    let u_signature = SignatureKeyPair::new();
    let u_encryption = EncryptionKeyPair::new();
    let u_cred = judge_key.obtain();

    let u2_signature = SignatureKeyPair::new();
    let u2_encryption = EncryptionKeyPair::new();
    let u2_cred = judge_key.obtain();


    // creating ticket distributor "D" key
    let d_signature = SignatureKeyPair::new();
    let d_encryption  = EncryptionKeyPair::new();

    // creating ticket transfer "T" key
    let t_signature = SignatureKeyPair::new();
    let t_encryption  = EncryptionKeyPair::new();

    // creating ticket validator "V" key. We also certified the key of V using D
    let v_signature = SignatureKeyPair::new();
    let v_encryption  = EncryptionKeyPair::new();
    let cert_v = d_signature.sign(
        key_to_bytes(
            &v_signature,
            &v_encryption
        ).as_slice()
    );

    let mut timing = Timing::new();

    const NB_EXECUTIONS : usize = NB_ITERATIONS;
    let mut executions_done = 0;
    for iteration in 1..=NB_ITERATIONS {
        let execution_start = Instant::now();
        println!("Progression: {}% ({}/{}): ",
                 (iteration as f64 / NB_EXECUTIONS as f64) * 100.0,
                 iteration, NB_EXECUTIONS
        );

        let mut next_tickets = Vec::new();
        let mut next_state = SharedState::new();
        // N * Purchase + N * Transfer + N * Refund
        {
            // we create the shared state between the different entities
            let mut state = SharedState::new();
            // we also maintains a list of tickets, used only for the purpose of the benchmarking
            let mut tickets: Vec<Ticket> = Vec::new();
            for billet in 0..NB_BILLETS {
                timing.start(String::from("purchase"));

                //let start = timing.start();
                
                let ticket = purchase(
                    &mut timing,
                    String::from("purchase"),
                    billet,
                    &mut state,
                    &mapper,
                    &d_signature,
                    &d_encryption,
                    &IDE,
                    &IDP
                ).unwrap();

                //timing.pause(   String::from("purchase"));
                //timing.stop(NB_BILLETS, iteration, &purchase_subject, start);

                timing.stop_all(billet);
                tickets.push(ticket)
            }

            // Then we do the transfer of the tickets
            let mut new_tickets = Vec::new();
            for (billet, ticket) in tickets.iter().enumerate() {
                //let start = timing.start();
                timing.start(String::from("transfer"));
                
                let transferred_ticket = transfer(
                    &mut state,
                    &mut timing,
                    billet,
                    ticket,
                    &t_encryption,
                    &t_signature,
                    &d_encryption,
                    &d_signature,
                    &u_encryption,
                    &u_signature,
                    &u2_encryption,
                    &u2_signature,
                    &mapper
                );
                
                //timing.stop(NB_BILLETS, i, &transfer_subject, start);
                //timing.stop(billet, "transfer");

                timing.stop_all(billet);

                // every ticket has to be refund since there are all valid
                assert_eq!(transferred_ticket.is_some(), true);
                new_tickets.push(transferred_ticket.unwrap());
            }
            let tickets = new_tickets;

            next_state = state.clone();
            next_tickets = tickets.clone();

            // Then, we do the refund of the tickets
            for (billet, ticket) in tickets.iter().enumerate() {
                //let start = timing.start();
                timing.start(String::from("refund"));

                let ticket_is_refund = refund(
                    &mut state,
                    &mut timing,
                    String::from("refund"),
                    ticket,
                    &mapper,
                    &t_encryption,
                    &d_encryption,
                    &t_signature,
                    &d_signature
                );
                
                //timing.stop( billet, "refund"  );
                //timing.stop(NB_BILLETS, i, &refund_subject, start);
                timing.stop_all(billet);

                // every ticket has to be refund since there are all valid
                assert_eq!(ticket_is_refund, true);
            }
        }


        // N * Purchase + N * Transfer + N * Validate
        {

            let mut tickets = next_tickets;
            let mut state = next_state;

            // Then we do the validation of the tickets.
            for (billet, ticket) in tickets.iter().enumerate() {
                //let start = timing.start();
                timing.start(String::from("validate"));

                let ticket_is_valid = validation(
                    &mut state,
                    &mut timing,
                    &mapper,
                    &d_signature,
                    &t_signature,
                    &t_encryption,
                    &u_signature,
                    &u_encryption,
                    &cert_v,
                    &v_encryption,
                    &v_signature,
                    ticket,
                    &mut judge_key,
                    &u_cred,
                    enable_audit
                );
               
                //timing.stop(billet, "validate");
                //timing.stop(NB_BILLETS, i, &validate_subject, start);
                timing.stop_all(billet);

                //  every ticket has to be validated since there are all valid
                assert!(ticket_is_valid);
            }
        }

        let execution_duration = execution_start.elapsed();
        println!("Done in {}ms", execution_duration.as_millis());
        executions_done += 1;

        println!("Exporting...");
        timing.export_at( proto_name.clone(), NB_ITERATIONS, NB_BILLETS);

    }


    
}

fn key_to_bytes( signature_key : &SignatureKeyPair, encryption_key : &EncryptionKeyPair ) -> Vec<u8> {
    let mut content_to_sign : Vec<u8> = Vec::new();
    content_to_sign.append(&mut signature_key.public_key_to_bytes().clone().to_vec());
    content_to_sign.append( &mut encryption_key.public_key_to_bytes().clone().to_vec() );
    content_to_sign
}

fn encrypt_ticket( ticket : &Ticket, _mapper : &PointMapper, encryption : &EncryptionKeyPair ) ->
                                                                                               Vec<Ciphertext> {
    let (_, _, r_c, signature) = ticket;
    let mut plaintext = Vec::new();
    plaintext.push(IDE);
    plaintext.push(IDP);
    plaintext.append(&mut r_c.clone());
    plaintext.append( &mut signature.to_vec().clone() );
    encryption.encrypt(&plaintext)
}

fn decrypt_ticket( encryption : &EncryptionKeyPair, mapper : &PointMapper, ciphertext : &Vec<Ciphertext> ) -> Ticket {
    let plaintext = encryption.decrypt(&mapper, &ciphertext);
    let r_c = &plaintext[2..2+SEC_PAR_BYTES].to_vec();
    let signature = Signature::from_slice(
        &plaintext[2+SEC_PAR_BYTES..]
    );
    (IDE, IDP, r_c.clone(), signature.unwrap())
}

fn hash_ticket( ticket : &Ticket ) -> Hash {
    let (IDE, IDP, r_c, _) = ticket else { todo!() };
    let mut hasher = Sha256::new();
    let mut plaintext = Vec::new();
    plaintext.push(IDE);
    plaintext.push(IDP);
    plaintext.append(&mut r_c.clone());
    hasher.update(&plaintext);
    let c : Hash = hasher.finalize().to_vec();
    c
}

fn check_ticket(
    state : &mut SharedState,
    timing : &mut Timing,
    subject : String,
    ticket : &Ticket,
    t_signature : &SignatureKeyPair,
    d_signature : &SignatureKeyPair,
    insert_ticket_if_valid : bool
) -> bool {

    
    // parse the ticket
    timing.start(format!("{}-crypto", subject));
    let (_, _, _, signature) = ticket;

    // compute the hash c = H(ide, idp, c)
    let c : Hash = hash_ticket(&ticket);

    // verify the signature
    let verified_signature = t_signature.verify(c.as_slice(), &signature) || d_signature.verify(&c, &signature);
    timing.pause(format!("{}-crypto", subject));

    timing.start(format!("{}-state", subject));
    let valid_ticket = !state.contains_ticket( &c );
   

    // in case where the ticket is valid, insert it in the shared state to prevent double-spending
    if verified_signature && valid_ticket {
        if insert_ticket_if_valid {
            state.add_ticket( c );
        }
        timing.pause(format!("{}-state", subject));
        true
    } else {
        timing.pause(format!("{}-state", subject));
        false
    }
    
}

fn payment() -> bool{
    // The payment function is not included in the protocol implementation
    true
}

fn purchase(
    timing : &mut Timing,
    subject : String,
    billet_index  : usize,
    state : &mut SharedState,
    mapper : &PointMapper,
    signature: &SignatureKeyPair,
    d_encryption : &EncryptionKeyPair,
    event_id : &IdeSpace,
    place_id : &IdpSpace
) -> Option<Ticket> {
   
    timing.start(format!("{}-crypto", subject));
    
   
      

  

    // generation of the random r_c
    let r_c: Vec<u8> = (0..SEC_PAR_BYTES).map(|_| { rand::random::<u8>() }).collect();

    // computation of the c = H(ide, idp, r_c)
    let mut hasher = Sha256::new();
    let mut plaintext = Vec::new();
    plaintext.push( *event_id);
    plaintext.push(*place_id);
    plaintext.append(&mut r_c.clone());
    hasher.update(&plaintext);
    let c : Hash = hasher.finalize().to_vec();
    assert_eq!(c.len(), 32);

    // encrypt and decrypt (ide, idp and r_c)
    let mut plaintext = Vec::new();
    plaintext.push(*event_id);
    plaintext.push(*place_id);
    plaintext.append(&mut r_c.clone());
    let ciphertext = d_encryption.encrypt(&plaintext);

    // decrypts the ciphertext containing (ide, idp, r_c)
    let _plaintext = d_encryption.decrypt(&mapper, &ciphertext);
    timing.pause(format!("{}-crypto", subject));


    // we check that ticket was not already included in the shared state
    timing.start(format!("{}-state", subject));
    if state.contains_ticket(&c) {
        return None;
    }

    state.add_ticket( c.clone() );
    state.remove_ticket(&c);
    timing.pause(format!("{}-state", subject));

    Some((*event_id, *place_id, r_c, signature.sign(c.as_slice())))
   
}

fn refund(
    state : &mut SharedState,
    timing : &mut Timing,
    subject : String,
    ticket : &Ticket,
    mapper : &PointMapper,
    _t_encryption : &EncryptionKeyPair,
    d_encryption : &EncryptionKeyPair,
    t_signature : &SignatureKeyPair,
    d_signature : &SignatureKeyPair
) -> bool {
    
    timing.start(format!("{}-crypto", subject));
    let ct = encrypt_ticket(ticket, mapper, d_encryption);
    let received_tk_d = decrypt_ticket(d_encryption, mapper, &ct);
    timing.pause(format!("{}-crypto", subject));


    
    let is_valid = check_ticket(state, timing, subject, &received_tk_d,  t_signature, d_signature, true);



    is_valid
}


fn transfer(
    state : &mut SharedState,
    timing : &mut Timing,
    billet_index  : usize,
    ticket : &Ticket,
    t_encryption :  &EncryptionKeyPair,
    t_signature : &SignatureKeyPair,
    d_encryption : &EncryptionKeyPair,
    d_signature : &SignatureKeyPair,
    u_encryption : &EncryptionKeyPair,
    u_signature : &SignatureKeyPair,
    u2_encryption : &EncryptionKeyPair,
    u2_signature : &SignatureKeyPair,
    mapper : &PointMapper
) -> Option<Ticket> {
    // every users start by randomizing these keys
    let randomized_u_encryption = u_encryption.randomize();
    let randomized_u_signature = u_signature.randomize();
    let randomized_u2_encryption = u2_encryption.randomize();
    let randomized_u2_signature = u2_signature.randomize();


    timing.start(String::from("transfer-crypto"));
    // User 1 ----------------------------------------------------------------------------------
    let (event_id, place_id, _, _) = ticket;
    // computation of c
    let c = hash_ticket( ticket );

    // computation of sigma_T_1
    let mut content_to_sign = Vec::new();
    for byte in randomized_u2_signature.public_key_to_bytes() {
        content_to_sign.push(byte);
    }
    for byte in randomized_u2_encryption.public_key_to_bytes() {
        content_to_sign.push(byte)
    }
    for byte in c {
        content_to_sign.push(byte);
    }
    let sigma_t_1 = randomized_u_signature.sign(content_to_sign.as_slice());


    // encryption of tk
    let ct_tk = encrypt_ticket(
        ticket,
        mapper,
        t_encryption
    );
    

    // User 2 ----------------------------------------------------------------------------------
    // signature of randomized key of u1
    let mut content_to_sign = Vec::new();
    for byte in randomized_u_signature.public_key_to_bytes() {
        content_to_sign.push(byte);
    }
    for byte in randomized_u_encryption.public_key_to_bytes() {
        content_to_sign.push(byte)
    }
    content_to_sign.push(IDE);
    content_to_sign.push(IDP);
    let sigma_t_2 = randomized_u2_signature.sign(content_to_sign.as_slice());



    // T ---------------------------------------------------------------------------------------
    // decrypt and hash the ticket
    let tk = decrypt_ticket(t_encryption, mapper, &ct_tk);
    let c = hash_ticket(&tk);

    // check sigma_T_1
    let mut content_to_verify = Vec::new();
    for byte in randomized_u2_signature.public_key_to_bytes() {
        content_to_verify.push(byte);
    }
    for byte in randomized_u2_encryption.public_key_to_bytes() {
        content_to_verify.push(byte)
    }
    for byte in c {
        content_to_verify.push(byte);
    }

    let valid_signature_from_u1 = randomized_u_signature.verify(content_to_verify.as_slice(), &sigma_t_1);
    if ! valid_signature_from_u1 { return None }

    // check sigma_T_2
    let mut content_to_verify = Vec::new();
    for byte in randomized_u_signature.public_key_to_bytes() {
        content_to_verify.push(byte);
    }
    for byte in randomized_u_encryption.public_key_to_bytes() {
        content_to_verify.push(byte)
    }
    content_to_verify.push(IDE);
    content_to_verify.push(IDP);

    let valid_signature_from_u2 = randomized_u2_signature.verify(content_to_verify.as_slice(), &sigma_t_2);
    if ! valid_signature_from_u2 { return None }

    timing.pause(String::from("transfer-crypto"));

    // check the ticket
    let tk_is_valid = check_ticket(
        state,
        timing,
        String::from("transfer"),
        &tk,
        t_signature,
        d_signature,
        false
    );
    if !tk_is_valid { return None; }

    timing.start(String::from("transfer-crypto"));

    // the transfer validation signature is returned from T to U2
    let mut content_to_sign : Vec<u8> = Vec::new();
    content_to_sign.push(IDE);
    content_to_sign.push(IDP);
    content_to_sign.append(&mut randomized_u2_signature.public_key_to_bytes().clone().to_vec());
    content_to_sign.append(&mut randomized_u2_encryption.public_key_to_bytes().clone().to_vec
    ());
    content_to_sign.append(&mut randomized_u_signature.public_key_to_bytes().clone().to_vec());
    content_to_sign.append(&mut randomized_u_encryption.public_key_to_bytes().clone().to_vec());
    let signature_to_u2 = t_signature.sign(content_to_sign.as_slice());
    t_signature.verify(content_to_sign.as_slice(), &signature_to_u2);

    timing.pause(String::from("transfer-crypto"));

    // we perform a purchase between T and U2
    let new_ticket = match purchase(
        timing,
        String::from("transfer"),
        billet_index,
        state,
        mapper,
        t_signature,
        t_encryption,
        event_id,
        place_id
    ) {
        None => { return None }
        Some(ticket) => {
            ticket
        }
    };

    timing.start(String::from("transfer-crypto"));
    // generating the signature for U1
    let mut content_to_sign : Vec<u8> = Vec::new();
    content_to_sign.push(IDE);
    content_to_sign.push(IDP);
    content_to_sign.append(&mut randomized_u_signature.public_key_to_bytes().clone().to_vec());
    content_to_sign.append(&mut randomized_u_encryption.public_key_to_bytes().clone().to_vec());
    content_to_sign.append(&mut randomized_u2_signature.public_key_to_bytes().clone().to_vec());
    content_to_sign.append(&mut randomized_u2_encryption.public_key_to_bytes().clone().to_vec());
    let signature_to_u1 = t_signature.sign(content_to_sign.as_slice());
    if ! t_signature.verify( content_to_sign.as_slice(), &signature_to_u1 ) {
        return None
    }
    timing.pause(String::from("transfer-crypto"));

    // Refund the ticket of U1
    let valid_refund = refund(
        state,
        timing,
        String::from("transfer"),
        ticket,
        mapper,
        t_encryption,
        d_encryption,
        t_signature,
        d_signature
    );
    if valid_refund {
        Some(new_ticket)
    } else {
        None
    }
}

fn validation(
    state : &mut SharedState,
    timing : &mut Timing,
    mapper:  &PointMapper,
    d_signature : &SignatureKeyPair,
    t_signature : &SignatureKeyPair,
    t_encryption : &EncryptionKeyPair,
    u_signature : &SignatureKeyPair,
    u_encryption : &EncryptionKeyPair,
    cert_v : &Signature,
    v_encryption : &EncryptionKeyPair,
    v_signature : &SignatureKeyPair,
    ticket : &Ticket,
    judge_keys : &mut JudgeKey,
    u_cred : &Credential,
    enable_audit : bool
) -> bool {
    timing.start(String::from("validation-crypto"));

    // checks that the certificate is valid
    let uncertified_validator = d_signature.verify(
        key_to_bytes(&t_signature, &t_encryption).as_slice(),
        &cert_v,
    );
    if uncertified_validator { return false; }

    // we parse the ticket
    let (_, _, r_c, signature) = ticket;

    // randomized the key of U
    let randomized_u_signature = u_signature.randomize();
    let randomized_u_encryption = u_encryption.randomize();

    // encrypt the randomized key and the ticket tk
    let mut content_to_encrypt = key_to_bytes(
        &randomized_u_signature,
        &randomized_u_encryption
    );
    content_to_encrypt.push(IDE);
    content_to_encrypt.push(IDP);
    content_to_encrypt.append(&mut r_c.clone());
    content_to_encrypt.append( &mut signature.to_vec().clone() );
    let ct = v_encryption.encrypt(&content_to_encrypt);


    // if audit is asked, then generate a showing of the credential
    let proof : Option<Omega> = match enable_audit {
        false => None,
        true => {
            Some(judge_keys.show(u_cred))
        }
    };

    // V ---------------------------------------------------------------------------------------
    // decrypt the ciphertext containing the ticket
    v_encryption.decrypt(&mapper, &ct);

    timing.pause(String::from("validation-crypto"));

    if ! check_ticket(state, timing, String::from("validation"), ticket, t_signature, d_signature, true) {
        return false;
    }



    timing.start(String::from("validation-crypto"));

    // if audit is asked: Check the validity of the provided proof
    match proof {
        None => {}
        Some(proof) => {
            judge_keys.verify(proof);
        }
    };

    // generate a random s
    let mut rng = thread_rng();
    let s : Vec<u8> = (0..SEC_PAR_BYTES).map(|_| rng.gen::<u8>()).collect();

    // compute the encryption of s with the (randomized) encryption key
    // of U
    let ct_s = randomized_u_encryption.encrypt(&s);
    let ciphertext_to_bytes = |c : &Vec<Ciphertext>| -> Vec<u8> {
        let mut bytes : Vec<u8> = Vec::new();
        for ciphertext in c {
            let c0 = ciphertext.inner().0.compress().as_bytes().to_vec();
            let c1 = ciphertext.inner().1.compress().as_bytes().to_vec();
            bytes.append( &mut c0.clone() );
            bytes.append( &mut c1.clone() );
        }
        bytes
    };
    // sign the ciphertext with the signature key
    let _signature_ct_s = v_signature.sign(
        ciphertext_to_bytes(&ct_s).as_slice()
    );
    timing.pause(String::from("validation-crypto"));

    // The physical comparison is outside of the result
    true
}




#[allow(unused_variables)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
fn main() {
    // we start by benchmarking the primitive
    //bench_primitive();

    bench_functions_with_state( false );
    bench_functions_with_state( true );

    /*
    // test the judge key
    let mut judge_key = JudgeKey::new();
    let cred = judge_key.obtain();
    let proof = judge_key.show(&cred);
    let is_verified_proof = judge_key.verify(proof);
    println!("Verified? {}", is_verified_proof);
     */
    
}



