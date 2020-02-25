package main

import (
	"testing"
)

func BenchmarkSingleBPGeneration(b *testing.B) {
	var value int64 = 7
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateSingleBulletProof(value)
	}
}

func BenchmarkSingleBPVerification(b *testing.B) {
	var value int64 = 7
	proofSingle, commitmentSingle := GenerateSingleBulletProof(value)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifySingleBulletProof(proofSingle, commitmentSingle)
	}
}

func BenchmarkMultipleBPGeneration(b *testing.B) {
	valuesVector := []int64{10, 0, 0, 0, 0, 0, 0, 0}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateMultipleBulletProofs(valuesVector)
	}
}

func BenchmarkMultipleBPVerification(b *testing.B) {
	valuesVector := []int64{10, 0, 0, 0, 0, 0, 0, 0}
	proofMul, commitmentsMul := GenerateMultipleBulletProofs(valuesVector)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyMultipleBulletProofs(proofMul, commitmentsMul)
	}
}
