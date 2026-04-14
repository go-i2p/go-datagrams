package datagrams

import (
	"crypto/sha256"
	"fmt"

	i2cp "github.com/go-i2p/go-i2cp"
)

// destinationHash computes the SHA-256 hash of an I2P destination's wire format.
// This is used for destination hash fields in Datagram3, signature verification in Datagram2,
// and populating I2PAddr.DestinationHash in receive paths.
func destinationHash(dest *i2cp.Destination) ([32]byte, error) {
	destStream := i2cp.NewStream(nil)
	if err := dest.WriteToStream(destStream); err != nil {
		return [32]byte{}, fmt.Errorf("failed to serialize destination for hash: %w", err)
	}
	return sha256.Sum256(destStream.Bytes()), nil
}

// buildDatagram1Envelope constructs a Datagram1 envelope with signature.
// Format: from destination (391+ bytes wire format) + signature (64 bytes for Ed25519) + payload
//
// Per I2P specification:
// - For DSA_SHA1 signature type (legacy): Signs the SHA-256 hash of the payload
// - For Ed25519 (modern): Signs the payload directly
//
// Since go-i2cp exclusively uses Ed25519, this implementation always signs the payload directly.
//
// IMPORTANT: Per I2P specification, Datagram1 does NOT support offline signatures (LS2 offline keys).
func buildDatagram1Envelope(payload []byte, session I2CPSession) ([]byte, error) {
	// Per I2P specification, Datagram1 does NOT support offline signatures (LS2 offline keys).
	// The Java reference implementation (I2PDatagramMaker) throws IllegalArgumentException
	// if session.isOffline() returns true. We replicate this behavior here.
	// See: https://geti2p.net/spec/datagrams#notes
	if session.IsOffline() {
		return nil, fmt.Errorf("Datagram1 does not support offline signatures (LS2 offline keys); use Datagram2 (protocol %d) instead", ProtocolDatagram2)
	}

	// Get the session's signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key pair: %w", err)
	}

	// Get the local destination to include in the envelope
	localDest := session.Destination()
	if localDest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	// Serialize the destination using wire format (WriteToMessage)
	// Wire format: pubKey(256) + signingPubKey(128) + certificate = 391+ bytes
	destStream := i2cp.NewStream(nil)
	if err := localDest.WriteToMessage(destStream); err != nil {
		return nil, fmt.Errorf("failed to serialize destination: %w", err)
	}
	destBytes := destStream.Bytes()

	// Sign the payload (Ed25519 signs directly, not the hash)
	signature, err := keyPair.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Build envelope: destination + signature + payload
	envelope := make([]byte, len(destBytes)+len(signature)+len(payload))
	copy(envelope[0:], destBytes)
	copy(envelope[len(destBytes):], signature)
	copy(envelope[len(destBytes)+len(signature):], payload)

	return envelope, nil
}

// parseDatagram1Envelope extracts and verifies a Datagram1 envelope.
// Format: from destination (391+ bytes wire format) + signature (64 bytes for Ed25519) + payload
//
// The signature is verified using the sender's public key embedded in the destination.
// Returns the payload, from destination, and any error (including signature verification failure).
func parseDatagram1Envelope(data []byte, session I2CPSession) (payload []byte, from *i2cp.Destination, err error) {
	// Minimum size: Ed25519DestinationSize (391) + Ed25519SignatureLength (64) = 455 bytes
	if len(data) < MinDatagram1Overhead {
		return nil, nil, fmt.Errorf("Datagram1 envelope too short: %d bytes (need at least %d)", len(data), MinDatagram1Overhead)
	}

	// Parse destination from the envelope using wire format reader
	crypto := i2cp.NewCrypto()
	stream := i2cp.NewStream(data)
	from, err = i2cp.NewDestinationFromMessage(stream, crypto)
	if err != nil {
		return nil, nil, fmt.Errorf("Datagram1 failed to parse destination: %w", err)
	}

	// Calculate how many bytes were consumed by the destination (wire format)
	destStream := i2cp.NewStream(nil)
	if err := from.WriteToMessage(destStream); err != nil {
		return nil, nil, fmt.Errorf("Datagram1 failed to serialize destination: %w", err)
	}
	destLen := destStream.Len()

	// Check if there's enough data for signature + at least empty payload
	if len(data) < destLen+Ed25519SignatureLength {
		return nil, nil, fmt.Errorf("Datagram1 envelope too short after destination: %d bytes remaining (need at least %d for signature)", len(data)-destLen, Ed25519SignatureLength)
	}

	// Extract Ed25519 signature (fixed 64 bytes)
	signature := data[destLen : destLen+Ed25519SignatureLength]
	payload = data[destLen+Ed25519SignatureLength:]

	// Verify signature using the sender's destination public key
	// Per I2P spec: Ed25519 signs the payload directly (not the hash)
	if !from.VerifySignature(payload, signature) {
		return nil, nil, fmt.Errorf("Datagram1 signature verification failed")
	}

	return payload, from, nil
}

// buildDatagram2Envelope constructs a Datagram2 envelope with signature and replay prevention.
// Format: from destination (391+ bytes wire format) + flags (2 bytes) + [options] + payload + signature (64 bytes)
//
// The signature is computed over: target_dest_hash (32 bytes, not in datagram) + flags + [options] + payload
//
// Per I2P specification, the target destination hash provides replay prevention - the same
// signed payload sent to different destinations will have different valid signatures.
//
// This implementation supports Datagram2 with optional options (I2P Mapping format).
// Options may be nil or empty for datagrams without options.
// Returns the complete envelope or an error if signing fails.
func buildDatagram2Envelope(payload []byte, session I2CPSession, targetDestHash [32]byte) ([]byte, error) {
	return buildDatagram2EnvelopeWithOptions(payload, session, targetDestHash, nil)
}

// buildDatagram2EnvelopeWithOptions constructs a Datagram2 envelope with optional options field.
// Options may be nil or empty to omit the options field.
//
// NOTE: Datagram2 is designed to support offline signatures (LS2 offline keys), but this
// implementation does not yet support SENDING with offline signatures. The go-i2cp library
// would need to expose the transient signing key for this to be implemented.
// Receiving Datagram2 with offline signatures IS supported.
func buildDatagram2EnvelopeWithOptions(payload []byte, session I2CPSession, targetDestHash [32]byte, options *Options) ([]byte, error) {
	// Per I2P specification, Datagram2 supports offline signatures (unlike Datagram1 which does not).
	// However, this implementation cannot currently construct the offline signature block for
	// SENDING because go-i2cp does not expose the transient signing key.
	// Receiving/parsing offline signatures IS implemented.
	// See: https://geti2p.net/spec/datagrams#datagram2
	if session.IsOffline() {
		return nil, fmt.Errorf("Datagram2 sending with offline signatures (LS2 offline keys) is not yet supported; " +
			"go-i2cp would need to expose the transient signing key for this feature")
	}

	// Get the session's signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key pair: %w", err)
	}

	// Get the local destination to include in the envelope
	localDest := session.Destination()
	if localDest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	// Serialize the destination using wire format (WriteToMessage)
	// Wire format: pubKey(256) + signingPubKey(128) + certificate = 391+ bytes
	destStream := i2cp.NewStream(nil)
	if err := localDest.WriteToMessage(destStream); err != nil {
		return nil, fmt.Errorf("failed to serialize destination: %w", err)
	}
	destBytes := destStream.Bytes()

	// Build flags (2 bytes): version 0x02, options flag if options present
	// Bit order: 15 14 ... 3 2 1 0
	// Bits 3-0: Version = 0x02
	// Bit 4: Options flag = 1 if options present
	// Bit 5: Offline signature flag = 0 (not supported for sending)
	lowFlags := byte(0x02) // version 0x02
	var optionsBytes []byte
	if options != nil && !options.IsEmpty() {
		lowFlags |= 0x10 // set options flag
		var optErr error
		optionsBytes, optErr = options.Bytes()
		if optErr != nil {
			return nil, fmt.Errorf("failed to serialize options: %w", optErr)
		}
	}
	flags := []byte{0x00, lowFlags} // high byte = 0, low byte = version + flags

	// Build data to sign: targetDestHash + flags + options + payload
	// Per spec: "The signature is over the following fields:
	// 1. Prelude: The 32-byte hash of the target destination (not included in the datagram)
	// 2. flags
	// 3. options (if present)
	// 4. offline_signature (if present) - not present in this implementation
	// 5. payload"
	toSign := make([]byte, 32+2+len(optionsBytes)+len(payload))
	offset := 0
	copy(toSign[offset:], targetDestHash[:])
	offset += 32
	copy(toSign[offset:], flags)
	offset += 2
	if len(optionsBytes) > 0 {
		copy(toSign[offset:], optionsBytes)
		offset += len(optionsBytes)
	}
	copy(toSign[offset:], payload)

	// Sign with Ed25519 (always signs directly, not the hash)
	signature, err := keyPair.Sign(toSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Build envelope: destination + flags + options + payload + signature
	// Note: signature is at the END for Datagram2 (unlike Datagram1 where it's in the middle)
	envelope := make([]byte, len(destBytes)+2+len(optionsBytes)+len(payload)+len(signature))
	envOffset := 0
	copy(envelope[envOffset:], destBytes)
	envOffset += len(destBytes)
	copy(envelope[envOffset:], flags)
	envOffset += 2
	if len(optionsBytes) > 0 {
		copy(envelope[envOffset:], optionsBytes)
		envOffset += len(optionsBytes)
	}
	copy(envelope[envOffset:], payload)
	envOffset += len(payload)
	copy(envelope[envOffset:], signature)

	return envelope, nil
}

// buildDatagram3EnvelopeWithOptions constructs a Datagram3 envelope with optional options field.
// Format: fromhash(32) + flags(2) + [options] + payload
//
// Unlike Datagram2, Datagram3 is NOT signed - it only includes the sender's hash for repliability.
// This makes it lightweight but unauthenticated.
//
// Options may be nil or empty to omit the options field.
func buildDatagram3EnvelopeWithOptions(payload []byte, session I2CPSession, options *Options) ([]byte, error) {
	localDest := session.Destination()
	if localDest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	// Compute SHA-256 hash of the local destination
	fromHash, err := destinationHash(localDest)
	if err != nil {
		return nil, fmt.Errorf("failed to compute destination hash: %w", err)
	}

	// Build flags (2 bytes): version 0x03, options flag if options present
	// Bit order: 15 14 ... 3 2 1 0
	// Bits 3-0: Version = 0x03
	// Bit 4: Options flag = 1 if options present
	// Bits 5-15: Reserved (must be 0)
	lowFlags := byte(0x03) // version 0x03
	var optionsBytes []byte
	if options != nil && !options.IsEmpty() {
		lowFlags |= 0x10 // set options flag
		var optErr error
		optionsBytes, optErr = options.Bytes()
		if optErr != nil {
			return nil, fmt.Errorf("failed to serialize options: %w", optErr)
		}
	}

	// Build envelope: fromhash + flags + [options] + payload
	envelope := make([]byte, 32+2+len(optionsBytes)+len(payload))
	offset := 0
	copy(envelope[offset:], fromHash[:])
	offset += 32
	envelope[offset] = 0x00 // high byte = 0 (reserved)
	envelope[offset+1] = lowFlags
	offset += 2
	if len(optionsBytes) > 0 {
		copy(envelope[offset:], optionsBytes)
		offset += len(optionsBytes)
	}
	copy(envelope[offset:], payload)

	return envelope, nil
}

// parseDatagram2Flags validates and parses Datagram2 flags.
// Returns whether options and offline signature are present.
func parseDatagram2Flags(flags []byte) (hasOptions, hasOfflineSig bool, err error) {
	// Validate reserved bits (6-15) are zero per spec
	reservedMask := uint16(0xFFC0)
	flagsValue := uint16(flags[0])<<8 | uint16(flags[1])
	if flagsValue&reservedMask != 0 {
		return false, false, fmt.Errorf("Datagram2 has non-zero reserved flag bits: 0x%04x (reserved bits: 0x%04x)", flagsValue, flagsValue&reservedMask)
	}

	version := flags[1] & 0x0F
	if version != 0x02 {
		return false, false, fmt.Errorf("invalid Datagram2 version: 0x%02x (expected 0x02)", version)
	}

	hasOptions = (flags[1] & 0x10) != 0
	hasOfflineSig = (flags[1] & 0x20) != 0
	return hasOptions, hasOfflineSig, nil
}

// parseDatagram2OfflineSig parses, validates, and verifies an offline signature block.
// Returns the OfflineSignature, raw bytes, bytes consumed, and any error.
func parseDatagram2OfflineSig(data []byte, offset int, from *i2cp.Destination) (*OfflineSignature, []byte, int, error) {
	destSigType := uint16(7) // Ed25519

	offlineSig, offLen, offErr := OfflineSignatureFromBytes(data[offset:], destSigType)
	if offErr != nil {
		return nil, nil, 0, fmt.Errorf("Datagram2 failed to parse offline signature: %w", offErr)
	}

	if offlineSig.IsExpired() {
		return nil, nil, 0, fmt.Errorf("Datagram2 offline signature has expired (expired at %s)", offlineSig.Expires)
	}

	if verifyErr := offlineSig.Verify(from); verifyErr != nil {
		return nil, nil, 0, fmt.Errorf("Datagram2 offline signature authorization failed: %w", verifyErr)
	}

	rawBytes := data[offset : offset+offLen]
	return offlineSig, rawBytes, offLen, nil
}

// buildDatagram2VerifyData constructs the data that was signed for Datagram2 verification.
// Per I2P spec: targetDestHash + flags + options + offline_sig + payload
func buildDatagram2VerifyData(localDestHash [32]byte, flags, optionsBytes, offlineSigBytes, payload []byte) []byte {
	toVerify := make([]byte, 32+2+len(optionsBytes)+len(offlineSigBytes)+len(payload))
	offset := 0
	copy(toVerify[offset:], localDestHash[:])
	offset += 32
	copy(toVerify[offset:], flags)
	offset += 2
	if len(optionsBytes) > 0 {
		copy(toVerify[offset:], optionsBytes)
		offset += len(optionsBytes)
	}
	if len(offlineSigBytes) > 0 {
		copy(toVerify[offset:], offlineSigBytes)
		offset += len(offlineSigBytes)
	}
	copy(toVerify[offset:], payload)
	return toVerify
}

// verifyDatagram2Signature verifies the signature on a Datagram2 envelope.
// Uses the transient key if an offline signature is present, otherwise the sender's destination key.
func verifyDatagram2Signature(toVerify, signature []byte, from *i2cp.Destination, offlineSig *OfflineSignature) error {
	var valid bool
	if offlineSig != nil {
		valid = offlineSig.VerifyPayloadSignature(toVerify, signature)
	} else {
		valid = from.VerifySignature(toVerify, signature)
	}
	if !valid {
		return fmt.Errorf("Datagram2 signature verification failed (possible replay attack or wrong recipient)")
	}
	return nil
}

// parseDatagram2Envelope extracts and verifies a Datagram2 envelope with replay prevention.
// Format: from destination (391+ bytes wire format) + flags (2 bytes) + [options] + [offline_sig] + payload + signature (64 bytes)
//
// The signature must verify against: receiver_dest_hash + flags + options + offline_sig + payload
// This provides replay prevention - datagrams sent to different destinations will fail verification.
func parseDatagram2Envelope(data []byte, session I2CPSession) (payload []byte, from *i2cp.Destination, err error) {
	payload, from, _, err = parseDatagram2EnvelopeWithOptions(data, session)
	return payload, from, err
}

// parseDatagram2EnvelopeWithOptions extracts and verifies a Datagram2 envelope, returning options.
// Format: from destination (391+ bytes wire format) + flags (2 bytes) + [options] + [offline_sig] + payload + signature (64 bytes)
//
// The signature must verify against: receiver_dest_hash + flags + options + offline_sig + payload
// This provides replay prevention - datagrams sent to different destinations will fail verification.
//
// Returns the payload, from destination, parsed options (if present), and any error.
func parseDatagram2EnvelopeWithOptions(data []byte, session I2CPSession) (payload []byte, from *i2cp.Destination, options *Options, err error) {
	if len(data) < MinDatagram2Overhead {
		return nil, nil, nil, fmt.Errorf("Datagram2 envelope too short: %d bytes (need at least %d)", len(data), MinDatagram2Overhead)
	}

	// Parse destination from the envelope using wire format reader
	crypto := i2cp.NewCrypto()
	stream := i2cp.NewStream(data)
	from, err = i2cp.NewDestinationFromMessage(stream, crypto)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Datagram2 failed to parse destination: %w", err)
	}

	// Calculate how many bytes were consumed by the destination
	destStream := i2cp.NewStream(nil)
	if err := from.WriteToMessage(destStream); err != nil {
		return nil, nil, nil, fmt.Errorf("Datagram2 failed to serialize destination: %w", err)
	}
	destLen := destStream.Len()

	if len(data) < destLen+2+Ed25519SignatureLength {
		return nil, nil, nil, fmt.Errorf("Datagram2 envelope too short after destination: have %d bytes remaining, need at least %d (flags: 2, signature: %d)", len(data)-destLen, 2+Ed25519SignatureLength, Ed25519SignatureLength)
	}

	// Extract and validate flags
	flags := data[destLen : destLen+2]
	hasOptions, hasOfflineSig, flagErr := parseDatagram2Flags(flags)
	if flagErr != nil {
		return nil, nil, nil, flagErr
	}

	offset := destLen + 2
	var optionsBytes []byte
	var offlineSigBytes []byte

	// Parse options if present
	if hasOptions {
		if len(data)-offset < 2 {
			return nil, nil, nil, fmt.Errorf("Datagram2 envelope too short for options size field at offset %d: have %d bytes, need at least 2", offset, len(data)-offset)
		}
		opts, optLen, optErr := OptionsFromBytes(data[offset:])
		if optErr != nil {
			return nil, nil, nil, fmt.Errorf("Datagram2 failed to parse options: %w", optErr)
		}
		optionsBytes = data[offset : offset+optLen]
		offset += optLen
		options = opts
	}

	// Parse and verify offline signature if present
	var offlineSig *OfflineSignature
	if hasOfflineSig {
		var offLen int
		offlineSig, offlineSigBytes, offLen, err = parseDatagram2OfflineSig(data, offset, from)
		if err != nil {
			return nil, nil, nil, err
		}
		offset += offLen
	}

	// Split payload and signature (signature is at end)
	if len(data)-offset < Ed25519SignatureLength {
		return nil, nil, nil, fmt.Errorf("Datagram2 envelope too short for signature at offset %d: have %d bytes, need %d", offset, len(data)-offset, Ed25519SignatureLength)
	}
	payloadEnd := len(data) - Ed25519SignatureLength
	payload = data[offset:payloadEnd]
	signature := data[payloadEnd:]

	// Compute local destination hash for replay prevention
	localDest := session.Destination()
	if localDest == nil {
		return nil, nil, nil, fmt.Errorf("session has no destination for verification")
	}
	localDestHash, err := destinationHash(localDest)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Datagram2 failed to compute local destination hash: %w", err)
	}

	// Build verification data and verify signature
	toVerify := buildDatagram2VerifyData(localDestHash, flags, optionsBytes, offlineSigBytes, payload)
	if err := verifyDatagram2Signature(toVerify, signature, from, offlineSig); err != nil {
		return nil, nil, nil, err
	}

	return payload, from, options, nil
}
