extern crate bincode;
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate libc;
extern crate rand;
use rand::thread_rng;

extern crate merlin;

use merlin::Transcript;
use curve25519_dalek::{ristretto::RistrettoPoint, ristretto::CompressedRistretto, scalar::Scalar};
use libc::{size_t, uint64_t, uint8_t};
use rand::rngs::OsRng;
use std::slice;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

#[no_mangle]
pub extern "C" fn generate(buf: *mut uint8_t, len: size_t) {
    let buffer = unsafe {
        assert!(!buf.is_null());
        slice::from_raw_parts_mut(buf, len as usize)
    };
    let mut rng = OsRng::new().unwrap();

    let point = RistrettoPoint::random(&mut rng);

    let point_bytes = point.compress().to_bytes();

    buffer.copy_from_slice(&point_bytes);

}



#[no_mangle]
pub extern "C" fn generate_ristretto_random(buf: *mut uint8_t, len: size_t) {
    let buffer = unsafe {
        assert!(!buf.is_null());
        slice::from_raw_parts_mut(buf, len as usize)
    };
    let mut rng = OsRng::new().unwrap();

    let point = RistrettoPoint::random(&mut rng);

    let point_bytes = point.compress().to_bytes();

    buffer.copy_from_slice(&point_bytes);
}

#[no_mangle]
pub extern "C" fn generate_ristretto_range_proof_single(
    val:*const uint64_t,
    proof_buf: *mut uint8_t,
    proof_buf_len: size_t,
    commitments_buf: *mut uint8_t,
    commitments_buf_len: size_t
) {
    // Unpack value
    let value = unsafe { *val };

    // The API takes blinding factors for the commitments.
    let blinding = Scalar::random(&mut thread_rng());
    
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();
    
    // Generators for Bulletproofs
    let bp_gens = BulletproofGens::new(32, 1);
    
    let mut transcript = Transcript::new(b"SingleRangeProof");

    let (proof, returned_commitments) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        value,
        &blinding,
        32,
    ).unwrap();

    let proof_buffer = unsafe {
        assert!(!proof_buf.is_null());
        slice::from_raw_parts_mut(proof_buf, proof_buf_len as usize)
    };

    let proof_bytes = bincode::serialize(&proof).unwrap();

    proof_buffer[..proof_bytes.len()].copy_from_slice(proof_bytes.as_slice());

    let commitments_buffer = unsafe {
        assert!(!commitments_buf.is_null());
        slice::from_raw_parts_mut(commitments_buf, commitments_buf_len as usize)
    };

    let commitments_bytes = bincode::serialize(&returned_commitments).unwrap();
    
    commitments_buffer[..commitments_bytes.len()].copy_from_slice(commitments_bytes.as_slice());
}

#[no_mangle]
pub extern "C" fn verify_ristretto_range_proof_single(
    proof_buf: *const uint8_t,
    proof_buf_len: size_t,
    commitment_buf:*const uint8_t,
    commitment_buf_len:size_t,
)-> bool{

    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();
    
    // Generators for Bulletproofs
    let bp_gens = BulletproofGens::new(32, 1);

    let proof_buffer = unsafe {
        assert!(!proof_buf.is_null());
        slice::from_raw_parts(proof_buf, proof_buf_len as usize)
    };

    let proof: RangeProof = bincode::deserialize(proof_buffer).unwrap();

    let commitment_buffer = unsafe {
        assert!(!commitment_buf.is_null());
        slice::from_raw_parts(commitment_buf, commitment_buf_len as usize)
    };

    let value_commitment: CompressedRistretto = bincode::deserialize(commitment_buffer).unwrap();
    
    let mut transcript = Transcript::new(b"SingleRangeProof");

    proof.verify_single(
        &bp_gens, &pc_gens, &mut transcript, &value_commitment, 32
    ).is_ok()

}



#[no_mangle]
pub extern "C" fn generate_ristretto_range_proof_multiple(
    vals:*const uint64_t,
    vals_len: size_t,
    proof_buf: *mut uint8_t,
    proof_buf_len: size_t,
    commitments_buf: *mut uint8_t,
    commitments_buf_len: size_t
) {
    // println!("Unpack values");
    let values = unsafe {
        assert!(!proof_buf.is_null());
        slice::from_raw_parts(vals, vals_len as usize)
    };

    // The API takes blinding factors for the commitments.
    let blindings: Vec<_> = (0..vals_len).map(|_| Scalar::random(&mut thread_rng())).collect();
    
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();
    
    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size is dyanmic according to passed values
    let aggregation_size = vals_len as usize;
    let bp_gens = BulletproofGens::new(32, aggregation_size);
    
    let mut transcript = Transcript::new(b"AggregatedRangeProof");

    let (proof, returned_commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &values,
        &blindings,
        32,
    ).unwrap();

    let proof_buffer = unsafe {
        assert!(!proof_buf.is_null());
        slice::from_raw_parts_mut(proof_buf, proof_buf_len as usize)
    };

    let proof_bytes = bincode::serialize(&proof).unwrap();

    proof_buffer[..proof_bytes.len()].copy_from_slice(proof_bytes.as_slice());

    let commitments_buffer = unsafe {
        assert!(!commitments_buf.is_null());
        slice::from_raw_parts_mut(commitments_buf, commitments_buf_len as usize)
    };

    let commitments_bytes = bincode::serialize(&returned_commitments).unwrap();
    
    commitments_buffer[..commitments_bytes.len()].copy_from_slice(commitments_bytes.as_slice());
}

#[no_mangle]
pub extern "C" fn verify_ristretto_range_proof_multiple(
    proof_buf: *const uint8_t,
    proof_buf_len: size_t,
    commitments_buf:*const uint8_t,
    commitments_buf_len:size_t,
)-> bool{

    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();
    
    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 16.
    let bp_gens = BulletproofGens::new(32, 16);

    let proof_buffer = unsafe {
        assert!(!proof_buf.is_null());
        slice::from_raw_parts(proof_buf, proof_buf_len as usize)
    };

    let proof: RangeProof = bincode::deserialize(proof_buffer).unwrap();

    let commitments_buffer = unsafe {
        assert!(!commitments_buf.is_null());
        slice::from_raw_parts(commitments_buf, commitments_buf_len as usize)
    };

    let value_commitments: Vec<CompressedRistretto> = bincode::deserialize(commitments_buffer).unwrap();
    
    let mut transcript = Transcript::new(b"AggregatedRangeProof");

    proof.verify_multiple(
        &bp_gens, &pc_gens, &mut transcript, &value_commitments, 32
    ).is_ok()

}

