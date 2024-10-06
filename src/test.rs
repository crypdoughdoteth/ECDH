use super::*;

#[test]
fn ecdh() {
    let alice_secret = Secret::gen_private_key();
    let alice_pub = alice_secret.derive_pubkey();
    let bob_secret = Secret::gen_private_key();
    let bob_pub = bob_secret.derive_pubkey();
    let a_diffie = EcDiffieHellman {
        counterparty_public_key: bob_pub,
        secret: alice_secret,
    };
    let b_diffie = EcDiffieHellman {
        counterparty_public_key: alice_pub,
        secret: bob_secret,
    };
    a_diffie.generate_shared_secret();
    // assert_eq!(
    //     a_diffie.generate_shared_secret(),
    //     b_diffie.generate_shared_secret()
    // )
}

