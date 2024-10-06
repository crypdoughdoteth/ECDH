use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{fields::fp::Fp, BigInteger, MontBackend};
use ark_secp256k1::{Affine, Fq, FqConfig, G_GENERATOR_X, G_GENERATOR_Y};
use ark_std::One;
use core::fmt;
use num_bigint::{BigInt, RandBigInt};
use rand::thread_rng;
use std::fmt::{Display, Formatter};
use tiny_keccak::{Hasher, Keccak};

const N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn main() {
    let pk = Secret::default();
    println!("{pk}");
    let points = pk.derive_pubkey();
    println!("{points}");
    println!("{}", EthereumAddress::from(&points));
    println!("{}", EthereumPrivateKey::from(&pk));
}

impl Secret {
    pub fn gen_private_key() -> Secret {
        let n: BigInt = BigInt::parse_bytes(N.as_bytes(), 16).unwrap();
        let mut rng = thread_rng();
        Secret(rng.gen_bigint_range(&BigInt::one(), &n))
    }

    pub fn derive_pubkey(&self) -> K1CurvePoint {
        let x = Fq::from(G_GENERATOR_X);
        let y = Fq::from(G_GENERATOR_Y);
        // AFFINE REQUIRES X, Y TO BE ON THE CURVE
        let g = Affine::new(x, y);
        let public_key = g.mul_bigint(&self.0.to_u64_digits().1).into_affine();
        K1CurvePoint {
            x: public_key.x,
            y: public_key.y,
        }
    }
}
pub type PublicKey = K1CurvePoint;
pub type PrivateKey = Secret;

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
        UncompressedPublicKey(format!("04{}{}", value.x, value.y))
    }
}

pub struct K1CurvePoint {
    x: Fp<MontBackend<FqConfig, 4>, 4>,
    y: Fp<MontBackend<FqConfig, 4>, 4>,
}

impl From<Secret> for K1CurvePoint {
    fn from(value: Secret) -> Self {
        value.derive_pubkey()
    }
}

impl Display for K1CurvePoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Public Key Curve Points:\nX: {}\nY: {}", self.x, self.y)
    }
}

#[derive(Debug)]
pub struct EthereumAddress(pub String);

impl Display for EthereumAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ethereum Address: {}", self.0)
    }
}

impl Display for EthereumPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ethereum Private Key: {}", self.0)
    }
}

#[derive(Debug)]
pub struct EthereumPrivateKey(pub String);

impl From<&Secret> for EthereumPrivateKey {
    fn from(value: &Secret) -> Self {
        let mut hasher = Keccak::v256();
        let mut pk_buffer = [0u8; 32];
        hasher.update(&value.0.to_bytes_be().1);
        hasher.finalize(&mut pk_buffer);
        EthereumPrivateKey(format!("0x{}", hex::encode(pk_buffer)))
    }
}

impl From<&K1CurvePoint> for EthereumAddress {
    fn from(value: &K1CurvePoint) -> Self {
        let mut pubkey_buffer: Vec<u8> = Vec::with_capacity(64);
        pubkey_buffer.extend_from_slice(&value.x.0.to_bytes_be());
        pubkey_buffer.extend_from_slice(&value.y.0.to_bytes_be());
        let mut hasher = Keccak::v256();
        let mut fixed_buffer = [0u8; 32];
        hasher.update(&pubkey_buffer);
        hasher.finalize(&mut fixed_buffer);
        let hashed: &[u8] = &fixed_buffer[12..];
        EthereumAddress(format!("0x{}", hex::encode(hashed)))
    }
}

pub struct EcDiffieHellman<'a> {
    counterparty_public_key: &'a K1CurvePoint,
    secret: &'a Secret,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SharedSecret(pub Fp<MontBackend<FqConfig, 4>, 4>);

impl SharedSecret {
    pub fn as_bigint(&self) -> ark_ff::BigInt<4> {
        self.0 .0
    }
}

impl<'a> EcDiffieHellman<'a> {
    pub fn generate_shared_secret(&self) -> SharedSecret {
        // curve point we want to multiply our secret by
        let q = Affine::new(
            self.counterparty_public_key.x,
            self.counterparty_public_key.y,
        );

        let public_key = q.mul_bigint(&self.secret.0.to_u64_digits().1).into_affine();
        SharedSecret(public_key.x)
    }
}

#[cfg(test)]
pub mod test {
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
