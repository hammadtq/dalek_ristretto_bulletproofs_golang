package main

/*
#cgo darwin LDFLAGS: -L./lib -lhello_ristretto
#include "./lib/hello_ristretto.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func main() {
	//generateRistrettoPointTwo()
	valuesVector := []int64{1, 1, 16, 56}
	proof, commitments := GenerateBulletProofs(valuesVector)
	fmt.Println("Proof is here:", proof)
	fmt.Println("Commitments are here:", commitments)

	VerifyBulletProofs(proof, commitments)
}

func generateRistrettoPoint() {
	buf := make([]byte, 32, 32)
	ptr := (*C.char)(unsafe.Pointer(&buf[0]))
	len := C.size_t(len(buf))
	C.generate(ptr, len)
	fmt.Printf("%v", buf)
}

func generateRistrettoPointTwo() {
	buf := make([]byte, 32, 32)
	ptr := (*C.char)(unsafe.Pointer(&buf[0]))
	len := C.size_t(len(buf))
	C.generate_ristretto_random(ptr, len)
	fmt.Printf("%v", buf)
}

// GenerateBulletProofs generates a range proof from dalek rust library using cgo
func GenerateBulletProofs(values []int64) ([]byte, []byte) {

	valuesLen := C.size_t(len(values))
	valuePtr := (*C.ulonglong)(unsafe.Pointer(&values[0]))

	proofBuf := make([]byte, 1000, 1000)
	proofBufPtr := (*C.uchar)(unsafe.Pointer(&proofBuf[0]))
	proofBufLen := C.size_t(len(proofBuf))

	valueCommitmentsBuf := make([]byte, 168)
	valueCommitmentsBufLen := C.size_t(len(valueCommitmentsBuf))
	valueCommitPtr := (*C.uchar)(unsafe.Pointer(&valueCommitmentsBuf[0]))
	C.generate_ristretto_range_proof(
		valuePtr,
		valuesLen,
		proofBufPtr,
		proofBufLen,
		valueCommitPtr,
		valueCommitmentsBufLen,
	)
	return proofBuf, valueCommitmentsBuf

}

// VerifyBulletProofs generates a range proof from dalek rust library using cgo
func VerifyBulletProofs(proof []byte, commitments []byte) {

	proofLen := C.size_t(len(proof))
	proofPtr := (*C.uchar)(unsafe.Pointer(&proof[0]))

	commitmentsLen := C.size_t(len(commitments))
	commtimentsPtr := (*C.uchar)(unsafe.Pointer(&commitments[0]))

	proofVerified := C.verify_ristretto_range_proof(
		proofPtr,
		proofLen,
		commtimentsPtr,
		commitmentsLen,
	)

	fmt.Println("Range Proof Verification result is:", proofVerified)
}
