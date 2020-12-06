use crate::amac::AMAC;
use crate::el_gamal::ElGamal;
use crate::d_ratchet::*;
use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

pub struct Platform {
    algm: AMAC,
    eg: ElGamal,
    bot: Scalar,
}

impl Platform {
    //new plat
    //gen mac keys
    //gen eg keys
    pub fn new(mut rng: &mut OsRng) -> Platform {
        let algm = AMAC::init(&mut rng);
        let eg = ElGamal::new(&mut rng);
        Platform {
            algm: algm,
            eg: eg,
            bot: Scalar::hash_from_bytes::<Sha512>(b"unused value"),
        }
    }

    //process message
    //verify proof
    //encrypt source
    //pass to receiver

    //validate receipt
    //verify proof
    //create new cert
    //pass to user

    //validate report
    //verify proof
    //decrypt
}

pub struct User {
    pub userid: RistrettoPoint,
    pub msg_scheme: SignalDR,
    ad: FD,
}

impl User {
    //new pair of users
    //ratchet keys
    //MAC creds
    pub fn new(mut rng: &mut OsRng, plat: &Platform) -> (User, User) {
        let uid1 = RistrettoPoint::random(&mut rng);
        let uid2 = RistrettoPoint::random(&mut rng);

        let ct1 = plat.eg.enc(rng, uid1);
        let mac1 = plat.algm.mac(rng, ct1.0, ct1.1, plat.bot);
        let ct2 = plat.eg.enc(rng, uid2);
        let mac2 = plat.algm.mac(rng, ct2.0, ct2.1, plat.bot);

        let (user1, user2) = pair_setup();

        (
            User {
                userid: uid1,
                msg_scheme: user1,
                ad: FD{ mac: mac1, src: ct1,},
            },
            User {
                userid: uid2,
                msg_scheme: user2,
                ad: FD{mac:mac2, src:ct2,},
            },
        )
    }

    //author message (non-interactive)
    //construct proof
    //encrypt openings
    //pass to plat
    //pub fn author(mut rng: &mut OsRng, )

    //forward message (NI)
    //construct proof
    //encrypt openings
    //pass to plat
    //receive
    //construct proof
    //pass to plat
    //get new cert from plat
    //verify cert
    //decrypt cert

    //generate report
    //create proof
}

pub struct FD {
    mac: (Scalar, RistrettoPoint, RistrettoPoint),
    src: (RistrettoPoint, RistrettoPoint),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn user_setup_test() {
        let mut rng = OsRng{};
        let plat = Platform::new(&mut rng);
        let (u1, u2) = User::new(&mut rng, &plat);

        plat.algm.verify(u1.ad.src.0, u1.ad.src.1, plat.bot, u1.ad.mac);
        plat.algm.verify(u2.ad.src.0, u2.ad.src.1, plat.bot, u2.ad.mac);
        let rsrc1 = plat.eg.dec(u1.ad.src);
        let rsrc2 = plat.eg.dec(u2.ad.src);
        assert_eq!(rsrc1, u1.userid);
        assert_eq!(rsrc2, u2.userid);

    }
}