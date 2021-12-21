use hex;
use rand::prelude::*;
use sha2::{Digest, Sha256};

const KEY_SIZE: usize = 256;
const KEY_ELEMENT_SIZE: usize = 32;

pub fn random_string() -> String {
     let str_bytes = rand::thread_rng().gen::<[u8; KEY_ELEMENT_SIZE]>();
     hex::encode(str_bytes)
}

pub struct PrivateKey {
     key_pairs: Vec<(String, String)>,
}

pub struct PublicKey {
     key_pairs: Vec<(String, String)>,
}

pub struct Signature {
     signatures: Vec<String>,
}

impl PrivateKey {
     pub fn get_key(&self, i: usize) -> (String, String) {
          self.key_pairs[i].clone()
     }
}

impl PublicKey {
     pub fn get_key(&self, i: usize) -> (String, String) {
          self.key_pairs[i].clone()
     }
}

impl Signature {
     pub fn get_key(&self, i: usize) -> String {
          self.signatures[i].clone()
     }
}

pub fn radom_private_key() -> PrivateKey {
     let mut private_key: Vec<(String, String)> = Vec::with_capacity(KEY_SIZE);
     for _i in 0..KEY_SIZE {
          private_key.push((random_string(), random_string()));
     }
     PrivateKey {
          key_pairs: private_key,
     }
}

fn hash(str: &str) -> String {
     let mut hasher = Sha256::new();
     hasher.update(str);
     hex::encode(hasher.finalize())
}

pub fn create_public_key(private_key: &PrivateKey) -> PublicKey {
     let mut public_key: Vec<(String, String)> = Vec::with_capacity(KEY_SIZE);
     for item in private_key.key_pairs.iter() {
          let (first_key, second_key) = item;
          public_key.push((hash(first_key), hash(second_key)));
     }
     PublicKey {
          key_pairs: public_key,
     }
}

fn hash_to_binary_array(hash_string: String) -> Vec<u8> {
     let message = hex::decode(hash_string);
     let mut str_binary_array: Vec<u8> = Vec::with_capacity(KEY_SIZE);
     match message {
          Ok(bytes) => {
               for byte in bytes.iter() {
                    for i in (0..8).rev() {
                         let bit = (byte >> i) & 1;
                         str_binary_array.push(bit);
                    }
               }
               str_binary_array
          }
          Err(_error) => str_binary_array,
     }
}

pub fn signature(message_hash: String, private_key: &PrivateKey) -> Signature {
     let message_binary_array = hash_to_binary_array(message_hash);
     let mut signature_array: Vec<String> = Vec::with_capacity(KEY_SIZE);
     for (index, item) in message_binary_array.iter().enumerate() {
          let (first_key, second_key) = private_key.get_key(index);
          if item.clone() == 0 {
               signature_array.push(first_key);
          } else {
               signature_array.push(second_key);
          }
     }
     Signature {
          signatures: signature_array,
     }
}

pub fn verify(message_hash: String, signature: &Signature, public_key: &PublicKey) -> bool {
     let message_binary_array = hash_to_binary_array(message_hash);
     for (index, item) in message_binary_array.iter().enumerate() {
          let sig = signature.get_key(index);
          let private_key_hash = hash(&sig);
          let (first_pub_key_hash, second_pub_key_hash) = public_key.get_key(index);
          if item.clone() == 0 {
               if private_key_hash != first_pub_key_hash {
                    return false;
               }
          } else {
               if private_key_hash != second_pub_key_hash {
                    return false;
               }
          }
     }
     return true;
}

pub fn execute() {
     let private_key = radom_private_key();
     let public_key = create_public_key(&private_key);

     let message = "Hello crypto";
     println!("==== Message =================");
     println!("{}", message);
     let message_hash = hash(message);
     println!("==== Message Hash =================");
     println!("{}", message_hash);

     let signuture = signature(message_hash, &private_key);
     println!("==== Signuture =================");
     println!("{:?}", signuture.signatures);

     let message_hash = hash(message);
     let veryfied = verify(message_hash, &signuture, &public_key);
     println!("==== Verify =================");
     println!("{}", veryfied);
}
