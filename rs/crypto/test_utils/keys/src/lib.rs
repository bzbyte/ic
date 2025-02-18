/// Contains various valid public keys that were generated by the Crypto component.
///
/// Useful for testing purposes when valid public keys are necessary but a dependency on
/// the code generating those keys may be undesired or not possible.
///
/// For each key type, the output of the corresponding key generation function was observed in a debugger
/// run inside the unit test for that function. Those tests are seeded (e.g., `ReproducibleRng)` and so
/// several runs of those tests leads to different keys.
pub mod public_keys {
    use crate::hex_decode;
    use ic_protobuf::registry::crypto::v1::{AlgorithmId, PublicKey, X509PublicKeyCert};

    //Node signing public key with node ID
    //4inqb-2zcvk-f6yql-sowol-vg3es-z24jd-jrkow-mhnsd-ukvfp-fak5p-aae
    pub fn valid_node_signing_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: hex_decode(
                "58d558c7586efb32f4667ee9a302877da97aa1136cda92af4d7a4f8873f9434f",
            ),
            proof_data: None,
            timestamp: None,
        }
    }

    pub fn valid_committee_signing_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MultiBls12381 as i32,
            key_value: hex_decode(
                "8dab94740858cc96e8df512d8d81730a94d0f3534f30\
                cebd35ee2006ce4a449cad611dd7d97bbc44256932da4d4a76a70b9f347e4a989a3073fc7\
                c2d51bf30804ebbc5c3c6da08b8392d2482473290aff428868caabbc26eec4e7bc59209eb0a",
            ),
            proof_data: Some(hex_decode(
                "afc3038c06223258a14af7c942428fe42f89f8d733e4f\
                5ea8d34a90c0df142697802a6f22633df890a1ce5b774b23aed",
            )),
            timestamp: None,
        }
    }

    pub fn valid_committee_signing_public_key_2() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MultiBls12381 as i32,
            key_value: hex_decode(
                "8fff9f51d3af56efde0be172831a6b835be4df818de3ea2bb3ac666eb7\
            9dcbe6393bac6f504ba490e6615988e285687f14c64d628a0262ee617d1c0a4aaaf500d44927bf0f849b3b\
            029b3aa994be55e5a9c67a91934b873ebc01b244f5a8bea0",
            ),
            proof_data: Some(hex_decode(
                "9984a0b02d25adba1af0058e65a297b81214f968c9ef04d0f1e8\
            6b827d604acb2de08a4340515a9e48abcc241ad49642",
            )),
            timestamp: None,
        }
    }

    // Has same node_id as valid_node_signing_public_key
    pub fn valid_tls_certificate() -> X509PublicKeyCert {
        X509PublicKeyCert {
            certificate_der: hex_decode(
                "3082015630820108a00302010202140098d074\
                7d24ca04a2f036d8665402b4ea784830300506032b6570304a3148304606035504030\
                c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673365732d7a3234\
                6a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d6161653020170d3\
                232313130343138313231345a180f39393939313233313233353935395a304a314830\
                4606035504030c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673\
                365732d7a32346a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d61\
                6165302a300506032b6570032100246acd5f38372411103768e91169dadb7370e9990\
                9a65639186ac6d1c36f3735300506032b6570034100d37e5ccfc32146767e5fd73343\
                649f5b5564eb78e6d8d424d8f01240708bc537a2a9bcbcf6c884136d18d2b475706d7\
                bb905f52faf28707735f1d90ab654380b",
            ),
        }
    }

    // Has same node_id as valid_node_signing_public_key
    pub fn valid_dkg_dealing_encryption_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::Groth20Bls12381 as i32,
            key_value: hex_decode(
                "ad36a01cbd40dcfa36ec21a96bedcab17372a9cd2b9eba6171ebeb28dd041a\
                    d5cbbdbb4bed55f59938e8ffb3dd69e386",
            ),
            proof_data: Some(hex_decode(
                "a1781847726f7468323057697468506f705f42\
                6c7331325f333831a367706f705f6b65795830b751c9585044139f80abdebf38d7f30\
                aeb282f178a5e8c284f279eaad1c90d9927e56cac0150646992bce54e08d317ea6963\
                68616c6c656e676558203bb20c5e9c75790f63aae921316912ffc80d6d03946dd21f8\
                5c35159ca030ec668726573706f6e7365582063d6cf189635c0f3111f97e69ae0af8f\
                1594b0f00938413d89dbafc326340384",
            )),
            timestamp: None,
        }
    }

    pub fn valid_dkg_dealing_encryption_public_key_2() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::Groth20Bls12381 as i32,
            key_value: hex_decode(
                "8a2804ac4c963d5013e7025af78a8fdae0e0274857a5f9c911148b6987\
            2449b8465a0603dc0f78ccbaa4f268d5ac55c8",
            ),
            proof_data: Some(hex_decode(
                "a1781847726f7468323057697468506f705f426c7331325f3338\
            31a367706f705f6b65795830920b3b9f9cfba7c6f50cd808e9411650c8ebea541db499b2103e91720c38ea\
            ed0a3e09a683ae4c5bee8f16e5c8a81fd1696368616c6c656e676558204432a1f6f054d076230ab13e30b8\
            bce264ef781a6996ff8cf0831b93654e606568726573706f6e7365582018fe3e9e21cd1c40f48590d93617\
            8e7df26d7a1d8172d480045f1f5e6afd387e",
            )),
            timestamp: None,
        }
    }

    pub fn valid_idkg_dealing_encryption_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MegaSecp256k1 as i32,
            key_value: hex_decode(
                "03e1e1f76e9d834221a26c4a080b65e60d3b6f9c1d6e5b880abf916a364893da2e",
            ),
            proof_data: None,
            timestamp: None,
        }
    }

    pub fn valid_idkg_dealing_encryption_public_key_2() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MegaSecp256k1 as i32,
            key_value: hex_decode(
                "02a649d6d5982b7d1b5f512db959995b8df73e3a09e64d38ad2c0eb8beb7f6fbc9",
            ),
            proof_data: None,
            timestamp: None,
        }
    }

    pub fn valid_idkg_dealing_encryption_public_key_3() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MegaSecp256k1 as i32,
            key_value: hex_decode(
                "033e771eceae50f124d589e3adb914c009b129a2e36a2f23e4ddf70f9911a53424",
            ),
            proof_data: None,
            timestamp: None,
        }
    }
}

fn hex_decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    hex::decode(data).expect("failed to decode hex")
}
