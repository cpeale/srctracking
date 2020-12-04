/*
* Implementation of algebraic mac based on the one 
* presented in The Signal Private Group System and Anonymous
* Credentials Supporting Efficient Verifiable Encryption, by 
* Chase et. al
*/
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

//For now: UIDs are ec points, can add attribute for metadata later

pub struct AMAC {
    //public group params
    //order: G_V, G_w, G_w', G_x0, G_x1, G_y1, G_y2, G_y3, G_m
    pub params: Vec<RistrettoPoint>,
    pub g: RistrettoPoint, //TODO: will maybe remove later

    //secret keys
    //order: w, w', x_0, x_1, y_1, y_2, y_3
    pub secrets: Vec<Scalar>,

    //issuance parameters
    pub cw: RistrettoPoint,
    pub i: RistrettoPoint,
}

//param constants
pub const G_V: usize = 0;
pub const G_W: usize = 1;
pub const G_W_P: usize = 2;
pub const G_X0: usize = 3;
pub const  G_X1: usize = 4;
pub const G_Y1: usize = 5;
pub const G_Y2: usize = 6;
pub const G_Y3: usize = 7;
pub const G_M: usize = 8;

//secret constants
pub const W: usize = 0;
pub const W_P: usize = 1;
pub const X_0: usize = 2;
pub const X_1: usize = 3;
pub const  Y_1: usize = 4;
pub const Y_2: usize = 5;
pub const Y_3: usize = 6;


impl AMAC {
    //keygen
    pub fn init(mut rng: &mut OsRng) -> AMAC {
        let v_params: Vec<RistrettoPoint> = (0..9).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let v_secrets: Vec<Scalar> = (0..7).map(|_| Scalar::random(&mut rng)).collect();
        AMAC {
            params: v_params.to_vec(),
            g: RistrettoPoint::random(&mut rng), //TODO: how to deal with this
            secrets: v_secrets.to_vec(),
            cw: (v_params[G_W] * v_secrets[W]) + (v_params[G_W_P] * v_secrets[W_P]),
            i: v_params[G_V] - ((v_params[G_X0] * v_secrets[X_0]) + (v_params[G_X1] * v_secrets[X_1]) + (v_params[G_Y1] * v_secrets[Y_1]) + (v_params[G_Y2] * v_secrets[Y_2]) + (v_params[G_Y3] * v_secrets[Y_3])),
        }
    }

    //MAC
    pub fn mac(&self, mut rng: &mut OsRng, e1:RistrettoPoint, e2: RistrettoPoint, m: Scalar) -> (Scalar, RistrettoPoint, RistrettoPoint) {
        //choose rand values
        let t = Scalar::random(rng);
        let u = RistrettoPoint::random(rng);
        (t, u, self.mac_from_vals(t, u, e1, e2, m))
    }

    fn mac_from_vals(&self, t: Scalar, u: RistrettoPoint, e1:RistrettoPoint, e2: RistrettoPoint, m: Scalar) -> RistrettoPoint {
        //compute scalar values
        let u_exp = self.secrets[X_0] + (self.secrets[X_1] * t);
        (self.params[G_W]*self.secrets[W]) + (u * u_exp) + (e1 * self.secrets[Y_1]) + (e2 * self.secrets[Y_2]) + ((self.params[G_M]*m)*self.secrets[Y_3])
    }

    //verify
    pub fn verify(&self, e1:RistrettoPoint, e2: RistrettoPoint, m: Scalar, mac: (Scalar, RistrettoPoint, RistrettoPoint)) {
        let (t, u, v) = mac;
        assert_eq!(v, self.mac_from_vals(t, u, e1, e2, m));
    }

    //blind issuance
    pub fn blind_issue(&self, mut rng: &mut OsRng, h: RistrettoPoint, a: (RistrettoPoint, RistrettoPoint), b: (RistrettoPoint, RistrettoPoint), c: (RistrettoPoint, RistrettoPoint)) -> ((Scalar, RistrettoPoint, (RistrettoPoint, RistrettoPoint)), Scalar) {
        let (a1, a2) = a;
        let (b1, b2) = b;
        let (c1, c2) = c;

        let (t, r) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let u = RistrettoPoint::random(&mut rng);

        let r1 = self.g * r;
        let u_exp = self.secrets[X_0] + (self.secrets[X_1]*t);
        let r2 = (h * r) + (self.params[G_W] * self.secrets[W]) + (u* u_exp);
        
        let s1 = (a1 * self.secrets[Y_1]) + (b1 * self.secrets[Y_2]) + (c1 * self.secrets[Y_3]) + r1;
        let s2 = (a2 * self.secrets[Y_1]) + (b2 * self.secrets[Y_2]) + (c2 * self.secrets[Y_3]) + r2;

        //TODO: proof
        ((t, u, (s1, s2)), r)
    }
}

pub fn eg_enc(mut rng: &mut OsRng, g: RistrettoPoint, pk: RistrettoPoint, m: RistrettoPoint) -> (RistrettoPoint, RistrettoPoint) {
    let r = Scalar::random(&mut rng);
    (g * r, (pk * r) + m)
}

pub fn eg_dec(sk: Scalar, ct: (RistrettoPoint, RistrettoPoint)) -> RistrettoPoint {
    let (c1, c2) = ct;
    c2 - (c1 * sk)
}

#[test]
fn basic_mac() {
    let mut rng = OsRng{};
    let algm = AMAC::init(&mut rng);
    let e1 = RistrettoPoint::random(&mut rng);
    let e2 = RistrettoPoint::random(&mut rng);
    let m = Scalar::random(&mut rng);
    let mac = algm.mac(&mut rng, e1, e2, m);
    algm.verify(e1, e2, m, mac);
}

#[test]
#[should_panic]
fn basic_mac_fail() {
    let mut rng = OsRng{};
    let algm = AMAC::init(&mut rng);
    let e1 = RistrettoPoint::random(&mut rng);
    let e2 = RistrettoPoint::random(&mut rng);
    let m = Scalar::random(&mut rng);
    let mac = algm.mac(&mut rng, e1, e2, m);

    let new_e1 = RistrettoPoint::random(&mut rng);
    algm.verify(new_e1, e2, m, mac);
}

#[test]
fn blind_mac() {
    let mut rng = OsRng{};
    let algm = AMAC::init(&mut rng);
    let e1 = RistrettoPoint::random(&mut rng);
    let e2 = RistrettoPoint::random(&mut rng);
    let m = Scalar::random(&mut rng);

    let gm = algm.params[G_M] * m;

    //eg setup
    let h = Scalar::random(&mut rng);
    let pk = algm.g * h;

    let (a, b, c) = (eg_enc(&mut rng, algm.g, pk, e1), eg_enc(&mut rng, algm.g, pk, e2), eg_enc(&mut rng, algm.g, pk, gm));
    let ((t, u, ct), r) = algm.blind_issue(&mut rng, pk, a, b, c);

    let v = eg_dec(h, ct);

    algm.verify(e1, e2, m, (t, u, v));
}

