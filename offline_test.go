package datagrams

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

// TestOfflineSignatureFromBytes_Ed25519 tests parsing an Ed25519 offline signature.
func TestOfflineSignatureFromBytes_Ed25519(t *testing.T) {
	// Build a minimal Ed25519 offline signature:
	// expires: 4 bytes (unix timestamp)
	// sigtype: 2 bytes (7 = Ed25519)
	// transient_public_key: 32 bytes (Ed25519 public key)
	// signature: 64 bytes (Ed25519 signature)
	// Total: 4 + 2 + 32 + 64 = 102 bytes

	expires := time.Now().Add(24 * time.Hour).Unix()

	data := make([]byte, 102)
	// expires (big-endian)
	data[0] = byte(expires >> 24)
	data[1] = byte(expires >> 16)
	data[2] = byte(expires >> 8)
	data[3] = byte(expires)
	// sigtype (7 = Ed25519)
	data[4] = 0x00
	data[5] = 0x07
	// transient public key (32 bytes of test data)
	for i := 0; i < 32; i++ {
		data[6+i] = byte(i)
	}
	// signature (64 bytes of test data)
	for i := 0; i < 64; i++ {
		data[38+i] = byte(i + 100)
	}

	offSig, consumed, err := OfflineSignatureFromBytes(data, 7) // Ed25519 destination
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if consumed != 102 {
		t.Errorf("expected 102 bytes consumed, got %d", consumed)
	}

	if offSig.TransientSigType != 7 {
		t.Errorf("expected sigtype 7, got %d", offSig.TransientSigType)
	}

	if len(offSig.TransientPublicKey) != 32 {
		t.Errorf("expected 32-byte public key, got %d", len(offSig.TransientPublicKey))
	}

	if len(offSig.Signature) != 64 {
		t.Errorf("expected 64-byte signature, got %d", len(offSig.Signature))
	}

	// Check public key content
	for i := 0; i < 32; i++ {
		if offSig.TransientPublicKey[i] != byte(i) {
			t.Errorf("public key byte %d: expected %d, got %d", i, i, offSig.TransientPublicKey[i])
		}
	}

	// Check signature content
	for i := 0; i < 64; i++ {
		if offSig.Signature[i] != byte(i+100) {
			t.Errorf("signature byte %d: expected %d, got %d", i, i+100, offSig.Signature[i])
		}
	}

	// Check expiration time (within 1 second tolerance)
	expectedExpires := time.Unix(expires, 0)
	if offSig.Expires.Sub(expectedExpires) > time.Second || expectedExpires.Sub(offSig.Expires) > time.Second {
		t.Errorf("expected expires %v, got %v", expectedExpires, offSig.Expires)
	}
}

// TestOfflineSignatureFromBytes_TooShort tests error handling for truncated data.
func TestOfflineSignatureFromBytes_TooShort(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"only_expires", []byte{0x00, 0x00, 0x00, 0x01}},
		{"only_header", []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x07}},
		{"truncated_pubkey", make([]byte, 30)}, // Need 6 + 32 + 64 = 102
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := OfflineSignatureFromBytes(tc.data, 7)
			if err == nil {
				t.Error("expected error for truncated data")
			}
		})
	}
}

// TestOfflineSignatureFromBytes_UnknownSigType tests error handling for unknown signature types.
func TestOfflineSignatureFromBytes_UnknownSigType(t *testing.T) {
	data := make([]byte, 102)
	// expires
	data[0] = 0x00
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x01
	// sigtype = 255 (unknown)
	data[4] = 0x00
	data[5] = 0xFF

	_, _, err := OfflineSignatureFromBytes(data, 7)
	if err == nil {
		t.Error("expected error for unknown signature type")
	}
}

// TestOfflineSignature_IsExpired tests expiration checking.
func TestOfflineSignature_IsExpired(t *testing.T) {
	// Test expired signature
	expiredSig := &OfflineSignature{
		Expires:            time.Now().Add(-1 * time.Hour),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 32),
		Signature:          make([]byte, 64),
	}

	if !expiredSig.IsExpired() {
		t.Error("expected signature to be expired")
	}

	// Test valid signature
	validSig := &OfflineSignature{
		Expires:            time.Now().Add(1 * time.Hour),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 32),
		Signature:          make([]byte, 64),
	}

	if validSig.IsExpired() {
		t.Error("expected signature to be valid")
	}
}

// TestOfflineSignature_Bytes tests encoding an offline signature.
func TestOfflineSignature_Bytes(t *testing.T) {
	expires := time.Unix(0x12345678, 0)
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 100)
	}

	offSig := &OfflineSignature{
		Expires:            expires,
		TransientSigType:   7,
		TransientPublicKey: pubKey,
		Signature:          sig,
	}

	data := offSig.Bytes()

	// Check expires (big-endian)
	if data[0] != 0x12 || data[1] != 0x34 || data[2] != 0x56 || data[3] != 0x78 {
		t.Errorf("wrong expires encoding: %x", data[0:4])
	}

	// Check sigtype
	if data[4] != 0x00 || data[5] != 0x07 {
		t.Errorf("wrong sigtype encoding: %x", data[4:6])
	}

	// Check public key
	if !bytes.Equal(data[6:38], pubKey) {
		t.Error("public key mismatch")
	}

	// Check signature
	if !bytes.Equal(data[38:], sig) {
		t.Error("signature mismatch")
	}
}

// TestOfflineSignature_Roundtrip tests encoding then decoding.
func TestOfflineSignature_Roundtrip(t *testing.T) {
	original := &OfflineSignature{
		Expires:            time.Unix(1234567890, 0),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 32),
		Signature:          make([]byte, 64),
	}
	for i := range original.TransientPublicKey {
		original.TransientPublicKey[i] = byte(i)
	}
	for i := range original.Signature {
		original.Signature[i] = byte(i + 50)
	}

	data := original.Bytes()

	parsed, consumed, err := OfflineSignatureFromBytes(data, 7)
	if err != nil {
		t.Fatalf("roundtrip parse error: %v", err)
	}

	if consumed != len(data) {
		t.Errorf("expected %d bytes consumed, got %d", len(data), consumed)
	}

	if !parsed.Expires.Equal(original.Expires) {
		t.Errorf("expires mismatch: %v vs %v", parsed.Expires, original.Expires)
	}

	if parsed.TransientSigType != original.TransientSigType {
		t.Errorf("sigtype mismatch: %d vs %d", parsed.TransientSigType, original.TransientSigType)
	}

	if !bytes.Equal(parsed.TransientPublicKey, original.TransientPublicKey) {
		t.Error("public key mismatch")
	}

	if !bytes.Equal(parsed.Signature, original.Signature) {
		t.Error("signature mismatch")
	}
}

// TestOfflineSignature_Len tests the Len() method.
func TestOfflineSignature_Len(t *testing.T) {
	// Ed25519: 4 + 2 + 32 + 64 = 102 bytes
	offSig := &OfflineSignature{
		Expires:            time.Now(),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 32),
		Signature:          make([]byte, 64),
	}

	if offSig.Len() != 102 {
		t.Errorf("expected len 102, got %d", offSig.Len())
	}

	// Also verify against actual encoded length
	data := offSig.Bytes()
	if len(data) != offSig.Len() {
		t.Errorf("encoded len %d != Len() %d", len(data), offSig.Len())
	}
}

// TestPublicKeyLengthForSigType tests the public key length lookup.
func TestPublicKeyLengthForSigType(t *testing.T) {
	testCases := []struct {
		sigType     uint16
		expectedLen int
	}{
		{0, 128}, // DSA_SHA1
		{1, 64},  // ECDSA_SHA256_P256
		{2, 96},  // ECDSA_SHA384_P384
		{3, 132}, // ECDSA_SHA512_P521
		{7, 32},  // Ed25519
		{11, 32}, // RedDSA_SHA512_Ed25519
		{99, 0},  // Unknown
		{255, 0}, // Unknown
	}

	for _, tc := range testCases {
		t.Run(string(rune('A'+tc.sigType)), func(t *testing.T) {
			got := publicKeyLengthForSigType(tc.sigType)
			if got != tc.expectedLen {
				t.Errorf("sigType %d: expected %d, got %d", tc.sigType, tc.expectedLen, got)
			}
		})
	}
}

// TestSignatureLengthForSigType tests the signature length lookup.
func TestSignatureLengthForSigType(t *testing.T) {
	testCases := []struct {
		sigType     uint16
		expectedLen int
	}{
		{0, 40},  // DSA_SHA1
		{1, 64},  // ECDSA_SHA256_P256
		{2, 96},  // ECDSA_SHA384_P384
		{3, 132}, // ECDSA_SHA512_P521
		{7, 64},  // Ed25519
		{11, 64}, // RedDSA_SHA512_Ed25519
		{99, 0},  // Unknown
		{255, 0}, // Unknown
	}

	for _, tc := range testCases {
		t.Run(string(rune('A'+tc.sigType)), func(t *testing.T) {
			got := signatureLengthForSigType(tc.sigType)
			if got != tc.expectedLen {
				t.Errorf("sigType %d: expected %d, got %d", tc.sigType, tc.expectedLen, got)
			}
		})
	}
}

// TestOfflineSignatureFromBytes_DSA tests parsing a DSA-SHA1 offline signature.
func TestOfflineSignatureFromBytes_DSA(t *testing.T) {
	// DSA_SHA1: 4 + 2 + 128 + 40 = 174 bytes
	expires := time.Now().Add(24 * time.Hour).Unix()

	data := make([]byte, 174)
	// expires (big-endian)
	data[0] = byte(expires >> 24)
	data[1] = byte(expires >> 16)
	data[2] = byte(expires >> 8)
	data[3] = byte(expires)
	// sigtype (0 = DSA_SHA1)
	data[4] = 0x00
	data[5] = 0x00
	// transient public key (128 bytes)
	for i := 0; i < 128; i++ {
		data[6+i] = byte(i)
	}
	// signature (40 bytes)
	for i := 0; i < 40; i++ {
		data[134+i] = byte(i + 100)
	}

	offSig, consumed, err := OfflineSignatureFromBytes(data, 0) // DSA destination
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if consumed != 174 {
		t.Errorf("expected 174 bytes consumed, got %d", consumed)
	}

	if offSig.TransientSigType != 0 {
		t.Errorf("expected sigtype 0, got %d", offSig.TransientSigType)
	}

	if len(offSig.TransientPublicKey) != 128 {
		t.Errorf("expected 128-byte public key, got %d", len(offSig.TransientPublicKey))
	}

	if len(offSig.Signature) != 40 {
		t.Errorf("expected 40-byte signature, got %d", len(offSig.Signature))
	}
}

// TestOfflineSignature_VerifyPayloadSignature tests payload signature verification
// using the transient key.
func TestOfflineSignature_VerifyPayloadSignature(t *testing.T) {
	// Generate an Ed25519 key pair for the transient key
	transientPub, transientPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate transient key: %v", err)
	}

	// Create an offline signature with the transient public key
	offSig := &OfflineSignature{
		Expires:            time.Now().Add(24 * time.Hour),
		TransientSigType:   7, // Ed25519
		TransientPublicKey: transientPub,
		Signature:          make([]byte, 64), // Authorization signature (not used in this test)
	}

	// Create a test message and sign it with the transient private key
	message := []byte("test message for signature verification")
	signature := ed25519.Sign(transientPriv, message)

	// Test: Valid signature should verify
	if !offSig.VerifyPayloadSignature(message, signature) {
		t.Error("expected valid signature to verify")
	}

	// Test: Wrong message should not verify
	wrongMessage := []byte("different message")
	if offSig.VerifyPayloadSignature(wrongMessage, signature) {
		t.Error("expected wrong message to fail verification")
	}

	// Test: Invalid signature should not verify
	invalidSig := make([]byte, 64)
	if offSig.VerifyPayloadSignature(message, invalidSig) {
		t.Error("expected invalid signature to fail verification")
	}

	// Test: Wrong signature length should not verify
	shortSig := make([]byte, 32)
	if offSig.VerifyPayloadSignature(message, shortSig) {
		t.Error("expected short signature to fail verification")
	}

	// Test: Non-Ed25519 sigtype should return false
	dsaOffSig := &OfflineSignature{
		Expires:            time.Now().Add(24 * time.Hour),
		TransientSigType:   0, // DSA_SHA1 - not supported
		TransientPublicKey: make([]byte, 128),
		Signature:          make([]byte, 40),
	}
	if dsaOffSig.VerifyPayloadSignature(message, signature) {
		t.Error("expected non-Ed25519 sigtype to fail verification")
	}
}

// TestOfflineSignature_VerifyPayloadSignature_WrongKeyLength tests that
// incorrect transient public key lengths are rejected.
func TestOfflineSignature_VerifyPayloadSignature_WrongKeyLength(t *testing.T) {
	message := []byte("test message")
	signature := make([]byte, 64)

	// Key too short
	shortKeySig := &OfflineSignature{
		Expires:            time.Now().Add(24 * time.Hour),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 16), // Should be 32
		Signature:          make([]byte, 64),
	}
	if shortKeySig.VerifyPayloadSignature(message, signature) {
		t.Error("expected short key to fail verification")
	}

	// Key too long
	longKeySig := &OfflineSignature{
		Expires:            time.Now().Add(24 * time.Hour),
		TransientSigType:   7,
		TransientPublicKey: make([]byte, 64), // Should be 32
		Signature:          make([]byte, 64),
	}
	if longKeySig.VerifyPayloadSignature(message, signature) {
		t.Error("expected long key to fail verification")
	}
}

// TestOfflineSignature_Verify tests verification of the offline signature
// against a destination's public key.
func TestOfflineSignature_Verify(t *testing.T) {
	// Generate a destination (which creates its own Ed25519 key pair internally)
	crypto := i2cp.NewCrypto()
	dest, err := i2cp.NewDestination(crypto)
	if err != nil {
		t.Fatalf("failed to create destination: %v", err)
	}

	// Get the signing key pair from the destination
	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("failed to get signing key pair: %v", err)
	}

	// Generate a transient key pair
	transientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate transient key: %v", err)
	}

	// Create the data to sign: expires + sigtype + transient_public_key
	expires := time.Now().Add(24 * time.Hour)
	dataToSign := make([]byte, 4+2+len(transientPub))
	binary.BigEndian.PutUint32(dataToSign[0:4], uint32(expires.Unix()))
	binary.BigEndian.PutUint16(dataToSign[4:6], 7) // Ed25519
	copy(dataToSign[6:], transientPub)

	// Sign with the destination's private key
	authSig, err := keyPair.Sign(dataToSign)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create the offline signature
	offSig := &OfflineSignature{
		Expires:            expires,
		TransientSigType:   7,
		TransientPublicKey: transientPub,
		Signature:          authSig,
	}

	// Test: Valid offline signature should verify
	if err := offSig.Verify(dest); err != nil {
		t.Errorf("expected valid offline signature to verify: %v", err)
	}

	// Test: Nil destination should error
	if err := offSig.Verify(nil); err == nil {
		t.Error("expected nil destination to fail verification")
	}

	// Test: Invalid signature should fail
	invalidOffSig := &OfflineSignature{
		Expires:            expires,
		TransientSigType:   7,
		TransientPublicKey: transientPub,
		Signature:          make([]byte, 64), // Zero signature
	}
	if err := invalidOffSig.Verify(dest); err == nil {
		t.Error("expected invalid signature to fail verification")
	}

	// Test: Wrong expiration time should fail (signature is over different data)
	wrongExpiresOffSig := &OfflineSignature{
		Expires:            expires.Add(1 * time.Second), // Different expiration
		TransientSigType:   7,
		TransientPublicKey: transientPub,
		Signature:          authSig,
	}
	if err := wrongExpiresOffSig.Verify(dest); err == nil {
		t.Error("expected wrong expiration to fail verification")
	}

	// Test: Wrong sigtype should fail
	wrongSigtypeOffSig := &OfflineSignature{
		Expires:            expires,
		TransientSigType:   11, // Different sigtype
		TransientPublicKey: transientPub,
		Signature:          authSig,
	}
	if err := wrongSigtypeOffSig.Verify(dest); err == nil {
		t.Error("expected wrong sigtype to fail verification")
	}
}

// TestOfflineSignature_Verify_DifferentDestination tests that offline signatures
// don't verify against different destinations.
func TestOfflineSignature_Verify_DifferentDestination(t *testing.T) {
	crypto := i2cp.NewCrypto()

	// Create first destination
	dest1, err := i2cp.NewDestination(crypto)
	if err != nil {
		t.Fatalf("failed to create destination 1: %v", err)
	}
	keyPair1, err := dest1.SigningKeyPair()
	if err != nil {
		t.Fatalf("failed to get key pair 1: %v", err)
	}

	// Create second destination (different key)
	dest2, err := i2cp.NewDestination(crypto)
	if err != nil {
		t.Fatalf("failed to create destination 2: %v", err)
	}

	// Generate a transient key pair
	transientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate transient key: %v", err)
	}

	// Create the data to sign
	expires := time.Now().Add(24 * time.Hour)
	dataToSign := make([]byte, 4+2+len(transientPub))
	binary.BigEndian.PutUint32(dataToSign[0:4], uint32(expires.Unix()))
	binary.BigEndian.PutUint16(dataToSign[4:6], 7)
	copy(dataToSign[6:], transientPub)

	// Sign with dest1's private key
	authSig, err := keyPair1.Sign(dataToSign)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	offSig := &OfflineSignature{
		Expires:            expires,
		TransientSigType:   7,
		TransientPublicKey: transientPub,
		Signature:          authSig,
	}

	// Should verify against dest1
	if err := offSig.Verify(dest1); err != nil {
		t.Errorf("expected to verify against signing destination: %v", err)
	}

	// Should NOT verify against dest2
	if err := offSig.Verify(dest2); err == nil {
		t.Error("expected verification to fail against different destination")
	}
}
