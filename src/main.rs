use ark_ec::{models::short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup};
use ark_secp256k1::{Affine, Config, Fq};
use ark_std::One;
use core::fmt;
use num_bigint::{BigInt, RandBigInt};
use rand::thread_rng;
use std::fmt::{Display, Formatter};

const N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn main() {
    let secret1 = Secret::default();
    let secret2 = Secret::default();
    let pubkey1 = secret1.derive_pubkey();
    let pubkey2 = secret2.derive_pubkey();
    let ss1 = EcDiffieHellman {
        counterparty_public_key: &pubkey2,
        secret: &secret1,
    }
    .generate_shared_secret();
    let ss2 = EcDiffieHellman {
        counterparty_public_key: &pubkey1,
        secret: &secret2,
    }
    .generate_shared_secret();
    assert_eq!(ss1, ss2);
    println!("Shared Secret: {:?}", ss1);
}

impl Secret {
    pub fn gen_private_key() -> Secret {
        let n: BigInt = BigInt::parse_bytes(N.as_bytes(), 16).unwrap();
        let mut rng = thread_rng();
        Secret(rng.gen_bigint_range(&BigInt::one(), &n))
    }

    pub fn derive_pubkey(&self) -> K1CurvePoint {
        K1CurvePoint(
            Config::GENERATOR
                .mul_bigint(&self.0.to_u64_digits().1)
                .into_affine(),
        )
    }
}

impl Default for Secret {
    fn default() -> Self {
        Self::gen_private_key()
    }
}

#[derive(Debug)]
pub struct Secret(BigInt);

impl Display for Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Secret Value: {:?}", self.0)
    }
}

pub struct UncompressedPublicKey(pub String);

impl From<&K1CurvePoint> for UncompressedPublicKey {
    fn from(value: &K1CurvePoint) -> Self {
        UncompressedPublicKey(format!("04{}{}", value.0.x, value.0.y))
    }
}

pub struct K1CurvePoint(Affine);

impl From<Secret> for K1CurvePoint {
    fn from(value: Secret) -> Self {
        value.derive_pubkey()
    }
}

impl Display for K1CurvePoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Public Key Curve Points:\nX: {}\nY: {}",
            self.0.x, self.0.y
        )
    }
}

pub struct EcDiffieHellman<'a> {
    counterparty_public_key: &'a K1CurvePoint,
    secret: &'a Secret,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SharedSecret(pub Fq);

impl SharedSecret {
    pub fn as_bigint(&self) -> ark_ff::BigInt<4> {
        self.0 .0
    }
}

impl<'a> EcDiffieHellman<'a> {
    pub fn generate_shared_secret(&self) -> SharedSecret {
        // curve point we want to multiply our secret by
        let q = self.counterparty_public_key;
        let public_key =
            q.0.mul_bigint(&self.secret.0.to_u64_digits().1)
                .into_affine();
        SharedSecret(public_key.x)
    }
}

#[cfg(test)]
pub mod test {
    use ark_ff::BigInteger;
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        ChaCha20Poly1305,
    };

    use super::*;

    #[test]
    fn ecdh() {
        let alice_secret = Secret::gen_private_key();
        let alice_pub = alice_secret.derive_pubkey();
        let bob_secret = Secret::gen_private_key();
        let bob_pub = bob_secret.derive_pubkey();
        let a_diffie = EcDiffieHellman {
            counterparty_public_key: &bob_pub,
            secret: &alice_secret,
        };
        let b_diffie = EcDiffieHellman {
            counterparty_public_key: &alice_pub,
            secret: &bob_secret,
        };
        let bob_shared_secret = b_diffie.generate_shared_secret();
        let alice_shared_secret = a_diffie.generate_shared_secret();
        assert_eq!(alice_shared_secret, bob_shared_secret,);

        let bob_int = bob_shared_secret.as_bigint();
        let alice_int = alice_shared_secret.as_bigint();
        let bob_cipher = ChaCha20Poly1305::new_from_slice(&bob_int.to_bytes_be()).unwrap();
        let alice_cipher = ChaCha20Poly1305::new_from_slice(&alice_int.to_bytes_be()).unwrap();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let ciphertext = bob_cipher
            .encrypt(&nonce, b"plaintext message".as_ref())
            .unwrap();
        let plaintext = alice_cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, b"plaintext message");
    }

    #[test]
    fn charlie_cant_steal() {
        let alice_secret = Secret::gen_private_key();
        let alice_pub = alice_secret.derive_pubkey();
        let bob_secret = Secret::gen_private_key();
        let bob_pub = bob_secret.derive_pubkey();
        let b_diffie = EcDiffieHellman {
            counterparty_public_key: &alice_pub,
            secret: &bob_secret,
        };
        let bob_int = b_diffie.generate_shared_secret().as_bigint();
        let bob_cipher = ChaCha20Poly1305::new_from_slice(&bob_int.to_bytes_be()).unwrap();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let ciphertext = bob_cipher
            .encrypt(&nonce, b"plaintext message".as_ref())
            .unwrap();

        // Charlie wants to steal Bob's and Alice's shared secret.
        let charlie_secret = Secret::gen_private_key();
        let _charlie_pub = charlie_secret.derive_pubkey();
        let c_diffie_bad = EcDiffieHellman {
            counterparty_public_key: &bob_pub,
            secret: &charlie_secret,
        };
        let charlie_shared_secret = c_diffie_bad.generate_shared_secret();
        assert_ne!(b_diffie.generate_shared_secret(), charlie_shared_secret);
        let charlie_secret = Secret::gen_private_key();
        let _charlie_pub = charlie_secret.derive_pubkey();
        let c_diffie_bad = EcDiffieHellman {
            counterparty_public_key: &bob_pub,
            secret: &charlie_secret,
        };
        let charlie_shared_secret = c_diffie_bad.generate_shared_secret();
        let charlie_int = charlie_shared_secret.as_bigint();
        let charlie_cipher = ChaCha20Poly1305::new_from_slice(&charlie_int.to_bytes_be()).unwrap();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        assert!(charlie_cipher.decrypt(&nonce, ciphertext.as_ref()).is_err());
    }
}
