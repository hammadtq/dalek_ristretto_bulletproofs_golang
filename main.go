package main

/*
#cgo darwin LDFLAGS: -L./lib -ldalek_rangeproofs
#include "./lib/dalek_rangeproofs.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func main() {
	
	var value int64 = 7
	proofSingle, commitmentSingle := GenerateSingleBulletProof(value) 
	fmt.Println("Single value Proof is here:", proofSingle)
	fmt.Println("Single value Commitment is here:", commitmentSingle)

	singleProofVerified := VerifySingleBulletProof(proofSingle, commitmentSingle)

	fmt.Println("Single Range Proof Verification result is:", singleProofVerified)

	valuesVector := []int64{68, 71, 51, 78, 90, 16, 18}
	// We need to pass in a value vector in power of 2
	if !IsPowerOfTwo(len(valuesVector)){
		valuesVector = append(valuesVector, 0)
	}

	proofMul, commitmentsMul := GenerateMultipleBulletProofs(valuesVector)
	fmt.Println("Multi-value Proof is here:", proofMul)
	fmt.Println("Mult-value Commitments are here:", commitmentsMul)

	mulProofVerified := VerifyMultipleBulletProofs(proofMul, commitmentsMul)

	fmt.Println("Multiple Range Proof Verification result is:", mulProofVerified)
}

func generateRistrettoPoint() {
	buf := make([]byte, 32, 32)
	ptr := (*C.char)(unsafe.Pointer(&buf[0]))
	len := C.size_t(len(buf))
	C.generate(ptr, len)
	fmt.Printf("%v", buf)
}

// GenerateSingleBulletProof generates a range proof from dalek rust library using cgo
func GenerateSingleBulletProof(value int64) ([]byte, []byte) {

	valuePtr := (*C.ulonglong)(unsafe.Pointer(&value))

	proofBuf := make([]byte, 700, 700)
	proofBufPtr := (*C.uchar)(unsafe.Pointer(&proofBuf[0]))
	proofBufLen := C.size_t(len(proofBuf))

	valueCommitmentsBuf := make([]byte, 40)
	valueCommitmentsBufLen := C.size_t(len(valueCommitmentsBuf))
	valueCommitPtr := (*C.uchar)(unsafe.Pointer(&valueCommitmentsBuf[0]))
	C.generate_ristretto_range_proof_single(
		valuePtr,
		proofBufPtr,
		proofBufLen,
		valueCommitPtr,
		valueCommitmentsBufLen,
	)
	return proofBuf, valueCommitmentsBuf

}

// VerifySingleBulletProof verifies a given range proof from dalek rust library using cgo
func VerifySingleBulletProof(proof []byte, commitments []byte) bool {

	proofLen := C.size_t(len(proof))
	proofPtr := (*C.uchar)(unsafe.Pointer(&proof[0]))

	commitmentsLen := C.size_t(len(commitments))
	commtimentsPtr := (*C.uchar)(unsafe.Pointer(&commitments[0]))

	proofVerified := C.verify_ristretto_range_proof_single(
		proofPtr,
		proofLen,
		commtimentsPtr,
		commitmentsLen,
	)

	if proofVerified == true{
		return true
	}
	return false
}

// GenerateMultipleBulletProofs generates a range proof from dalek rust library using cgo
func GenerateMultipleBulletProofs(values []int64) ([]byte, []byte) {

	valuesLen := C.size_t(len(values))
	valuePtr := (*C.ulonglong)(unsafe.Pointer(&values[0]))

	proofBuf := make([]byte, 1000, 1000)
	proofBufPtr := (*C.uchar)(unsafe.Pointer(&proofBuf[0]))
	proofBufLen := C.size_t(len(proofBuf))

	valueCommitmentsBuf := make([]byte, 336)
	valueCommitmentsBufLen := C.size_t(len(valueCommitmentsBuf))
	valueCommitPtr := (*C.uchar)(unsafe.Pointer(&valueCommitmentsBuf[0]))
	C.generate_ristretto_range_proof_multiple(
		valuePtr,
		valuesLen,
		proofBufPtr,
		proofBufLen,
		valueCommitPtr,
		valueCommitmentsBufLen,
	)
	return proofBuf, valueCommitmentsBuf

}

// VerifyMultipleBulletProofs verifies a given range proof from dalek rust library using cgo
func VerifyMultipleBulletProofs(proof []byte, commitments []byte) bool {

	proofLen := C.size_t(len(proof))
	proofPtr := (*C.uchar)(unsafe.Pointer(&proof[0]))

	commitmentsLen := C.size_t(len(commitments))
	commtimentsPtr := (*C.uchar)(unsafe.Pointer(&commitments[0]))

	proofVerified := C.verify_ristretto_range_proof_multiple(
		proofPtr,
		proofLen,
		commtimentsPtr,
		commitmentsLen,
	)

	if proofVerified == true{
		return true
	}
	return false
}

// IsPowerOfTwo checks if a given number is in the power of 2
func IsPowerOfTwo(x int) bool{
    return (x != 0) && ((x & (x - 1)) == 0);
}