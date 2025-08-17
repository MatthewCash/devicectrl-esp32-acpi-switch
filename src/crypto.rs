use anyhow::{Context, Result, anyhow};
use devicectrl_common::protocol::simple::SIGNATURE_LEN;
use esp_hal::{
    ecc::{Ecc, EllipticCurve},
    peripherals::{ECC, SHA},
    rng::Rng,
    sha::{Sha, Sha256, ShaAlgorithm},
};
use nb::block;
use p256::{
    EncodedPoint, FieldBytes, NistP256, ProjectivePoint, PublicKey, Scalar, SecretKey,
    elliptic_curve::{
        Field, PrimeField,
        ops::Reduce,
        point::AffineCoordinates,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use primeorder::PrimeCurveParams;

fn sha256_hash(sha: &mut SHA, data: &[u8]) -> Result<[u8; Sha256::DIGEST_LENGTH]> {
    let mut sha_driver = Sha::new(sha.reborrow());
    let mut hasher = sha_driver.start::<Sha256>();
    let mut hash_data = data;

    while !hash_data.is_empty() {
        hash_data = block!(hasher.update(hash_data))?;
    }

    let mut hash = [0u8; Sha256::DIGEST_LENGTH];
    block!(hasher.finish(&mut hash))?;

    Ok(hash)
}

pub fn ecdsa_sign(
    sha: &mut SHA,
    ecc: &mut ECC,
    rng_driver: &mut Rng,
    secret_key: &SecretKey,
    msg: &[u8],
) -> Result<[u8; SIGNATURE_LEN]> {
    let mut ecc_driver = Ecc::new(ecc.reborrow());

    let d = secret_key.to_nonzero_scalar();

    let msg_hash = sha256_hash(sha, msg)?;
    let z: Scalar = Scalar::reduce_bytes(&FieldBytes::from(msg_hash));

    let k = Scalar::random(rng_driver);
    let k_inv = k.invert().into_option().context("failed to invert k")?;

    let mut x = NistP256::GENERATOR.0.to_bytes();
    let mut y = NistP256::GENERATOR.1.to_bytes();

    ecc_driver
        .affine_point_multiplication(
            &EllipticCurve::P256,
            &k.to_bytes(),
            x.as_mut_slice(),
            y.as_mut_slice(),
        )
        .map_err(|e| anyhow!("{:?}", e))?;

    let r = Scalar::reduce_bytes(FieldBytes::from_slice(&x));

    // s = k^-1 * (z + r * d) mod n
    let s = k_inv * (z + (r * *d));

    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..SIGNATURE_LEN / 2].copy_from_slice(&r.to_repr());
    sig[SIGNATURE_LEN / 2..].copy_from_slice(&s.to_repr());
    Ok(sig)
}

pub fn ecdsa_verify(
    sha: &mut SHA,
    ecc: &mut ECC,
    public_key: &PublicKey,
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<bool> {
    let mut ecc_driver = Ecc::new(ecc.reborrow());

    let q_proj = public_key.to_encoded_point(false);

    let r = Scalar::reduce_bytes(FieldBytes::from_slice(&sig[..SIGNATURE_LEN / 2]));
    let s = Scalar::reduce_bytes(FieldBytes::from_slice(&sig[SIGNATURE_LEN / 2..]));

    if r.is_zero().into() || s.is_zero().into() {
        return Ok(false);
    }

    let msg_hash = sha256_hash(sha, msg)?;
    let z: Scalar = Scalar::reduce_bytes(&FieldBytes::from(msg_hash));

    let w = s.invert().into_option().context("failed to invert s")?;
    let u1 = z * w;
    let u2 = r * w;

    let p1 = {
        let mut x = NistP256::GENERATOR.0.to_bytes();
        let mut y = NistP256::GENERATOR.1.to_bytes();

        ecc_driver
            .affine_point_multiplication(
                &EllipticCurve::P256,
                &u1.to_bytes(),
                x.as_mut_slice(),
                y.as_mut_slice(),
            )
            .map_err(|e| anyhow!("{:?}", e))?;

        ProjectivePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(&x, &y, false))
    }
    .into_option()
    .context("failed to decode p1")?;

    let p2 = {
        let mut x = *q_proj.x().context("q_proj missing x")?;
        let mut y = *q_proj.y().context("q_proj missing y")?;

        ecc_driver
            .affine_point_multiplication(
                &EllipticCurve::P256,
                &u2.to_bytes(),
                x.as_mut_slice(),
                y.as_mut_slice(),
            )
            .map_err(|e| anyhow!("{:?}", e))?;

        ProjectivePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(&x, &y, false))
    }
    .into_option()
    .context("failed to decode p2")?;

    let rprime = (p1 + p2).to_affine();

    // Valid if x-coordinate of R' = r mod n
    let rprime_x = Scalar::from_repr(rprime.x())
        .into_option()
        .context("failed to create x_rprime value")?;

    Ok(rprime_x == r)
}
