package datagrams

import (
	"net"
	"testing"
)

// TestI2PAddr_Network verifies that I2PAddr implements net.Addr.Network() correctly.
func TestI2PAddr_Network(t *testing.T) {
	addr := &I2PAddr{
		Destination: "test.destination.i2p",
		Port:        8080,
	}

	got := addr.Network()
	want := "i2p"

	if got != want {
		t.Errorf("Network() = %q, want %q", got, want)
	}
}

// TestI2PAddr_String verifies string formatting of I2P addresses.
func TestI2PAddr_String(t *testing.T) {
	tests := []struct {
		name string
		addr *I2PAddr
		want string
	}{
		{
			name: "full address with short destination",
			addr: &I2PAddr{
				Destination: "short.i2p",
				Port:        8080,
			},
			want: "short.i2p:8080",
		},
		{
			name: "full address with long destination (truncated)",
			addr: &I2PAddr{
				Destination: "very-long-destination-string-that-exceeds-sixteen-characters",
				Port:        9000,
			},
			want: "very-long-destin...:9000",
		},
		{
			name: "anonymous sender (empty destination)",
			addr: &I2PAddr{
				Destination: "",
				Port:        8080,
			},
			want: ":8080",
		},
		{
			name: "zero port",
			addr: &I2PAddr{
				Destination: "test.i2p",
				Port:        0,
			},
			want: "test.i2p:0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseI2PAddr verifies parsing of I2P address strings.
func TestParseI2PAddr(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *I2PAddr
		wantErr bool
	}{
		{
			name:  "full address",
			input: "example.destination.i2p:8080",
			want: &I2PAddr{
				Destination: "example.destination.i2p",
				Port:        8080,
			},
			wantErr: false,
		},
		{
			name:  "destination only",
			input: "example.destination.i2p",
			want: &I2PAddr{
				Destination: "example.destination.i2p",
				Port:        0,
			},
			wantErr: false,
		},
		{
			name:  "port only",
			input: ":9000",
			want: &I2PAddr{
				Destination: "",
				Port:        9000,
			},
			wantErr: false,
		},
		{
			name:  "destination with colons and port",
			input: "base64:encoded:destination:12345",
			want: &I2PAddr{
				Destination: "base64:encoded:destination",
				Port:        12345,
			},
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid port (non-numeric)",
			input:   "example.i2p:invalid",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid port (out of range)",
			input:   "example.i2p:99999",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid port (negative)",
			input:   "example.i2p:-1",
			want:    nil,
			wantErr: true,
		},
		{
			name:  "max valid port",
			input: "example.i2p:65535",
			want: &I2PAddr{
				Destination: "example.i2p",
				Port:        65535,
			},
			wantErr: false,
		},
		{
			name:  "min valid port",
			input: "example.i2p:0",
			want: &I2PAddr{
				Destination: "example.i2p",
				Port:        0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseI2PAddr(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseI2PAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if !got.Equal(tt.want) {
				t.Errorf("ParseI2PAddr() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestI2PAddr_Equal verifies equality comparison between I2P addresses.
func TestI2PAddr_Equal(t *testing.T) {
	tests := []struct {
		name string
		a    *I2PAddr
		b    *I2PAddr
		want bool
	}{
		{
			name: "equal addresses",
			a: &I2PAddr{
				Destination: "test.i2p",
				Port:        8080,
			},
			b: &I2PAddr{
				Destination: "test.i2p",
				Port:        8080,
			},
			want: true,
		},
		{
			name: "different destinations",
			a: &I2PAddr{
				Destination: "test1.i2p",
				Port:        8080,
			},
			b: &I2PAddr{
				Destination: "test2.i2p",
				Port:        8080,
			},
			want: false,
		},
		{
			name: "different ports",
			a: &I2PAddr{
				Destination: "test.i2p",
				Port:        8080,
			},
			b: &I2PAddr{
				Destination: "test.i2p",
				Port:        9000,
			},
			want: false,
		},
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "one nil",
			a: &I2PAddr{
				Destination: "test.i2p",
				Port:        8080,
			},
			b:    nil,
			want: false,
		},
		{
			name: "empty destinations equal",
			a: &I2PAddr{
				Destination: "",
				Port:        8080,
			},
			b: &I2PAddr{
				Destination: "",
				Port:        8080,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.Equal(tt.b)
			if got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestI2PAddr_AsNetAddr verifies that I2PAddr can be used as net.Addr.
func TestI2PAddr_AsNetAddr(t *testing.T) {
	addr := &I2PAddr{
		Destination: "test.i2p",
		Port:        8080,
	}

	netAddr := addr.AsNetAddr()

	// Verify type assertion
	if _, ok := netAddr.(net.Addr); !ok {
		t.Error("AsNetAddr() does not return a net.Addr")
	}

	// Verify Network() method works through interface
	if netAddr.Network() != "i2p" {
		t.Errorf("Network() through net.Addr = %q, want %q", netAddr.Network(), "i2p")
	}

	// Verify String() method works through interface
	want := "test.i2p:8080"
	if netAddr.String() != want {
		t.Errorf("String() through net.Addr = %q, want %q", netAddr.String(), want)
	}
}

// TestI2PAddr_NetAddrInterface verifies I2PAddr satisfies net.Addr interface.
func TestI2PAddr_NetAddrInterface(t *testing.T) {
	var _ net.Addr = (*I2PAddr)(nil) // Compile-time interface check
}

// TestI2PAddr_HasFullDestination verifies the HasFullDestination method.
func TestI2PAddr_HasFullDestination(t *testing.T) {
	tests := []struct {
		name string
		addr *I2PAddr
		want bool
	}{
		{
			name: "has destination",
			addr: &I2PAddr{
				Destination: "test.i2p",
				Port:        8080,
			},
			want: true,
		},
		{
			name: "empty destination",
			addr: &I2PAddr{
				Destination: "",
				Port:        8080,
			},
			want: false,
		},
		{
			name: "hash only (Datagram3 style)",
			addr: &I2PAddr{
				Destination:     "",
				DestinationHash: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				Port:            8080,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.addr.HasFullDestination(); got != tt.want {
				t.Errorf("HasFullDestination() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestI2PAddr_HasDestinationHash verifies the HasDestinationHash method.
func TestI2PAddr_HasDestinationHash(t *testing.T) {
	tests := []struct {
		name string
		addr *I2PAddr
		want bool
	}{
		{
			name: "has hash",
			addr: &I2PAddr{
				DestinationHash: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				Port:            8080,
			},
			want: true,
		},
		{
			name: "zero hash",
			addr: &I2PAddr{
				Destination: "test.i2p",
				Port:        8080,
			},
			want: false,
		},
		{
			name: "all zeros hash",
			addr: &I2PAddr{
				DestinationHash: [32]byte{},
				Port:            8080,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.addr.HasDestinationHash(); got != tt.want {
				t.Errorf("HasDestinationHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestI2PAddr_IsHashOnly verifies the IsHashOnly method.
func TestI2PAddr_IsHashOnly(t *testing.T) {
	tests := []struct {
		name string
		addr *I2PAddr
		want bool
	}{
		{
			name: "hash only (Datagram3 style)",
			addr: &I2PAddr{
				Destination:     "",
				DestinationHash: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				Port:            8080,
			},
			want: true,
		},
		{
			name: "both destination and hash",
			addr: &I2PAddr{
				Destination:     "test.i2p",
				DestinationHash: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				Port:            8080,
			},
			want: false,
		},
		{
			name: "destination only",
			addr: &I2PAddr{
				Destination: "test.i2p",
				Port:        8080,
			},
			want: false,
		},
		{
			name: "neither destination nor hash",
			addr: &I2PAddr{
				Port: 8080,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.addr.IsHashOnly(); got != tt.want {
				t.Errorf("IsHashOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestI2PAddr_Equal_WithHash verifies equality comparison includes destination hash.
func TestI2PAddr_Equal_WithHash(t *testing.T) {
	hash1 := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	hash2 := [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	tests := []struct {
		name string
		a    *I2PAddr
		b    *I2PAddr
		want bool
	}{
		{
			name: "equal with same hash",
			a: &I2PAddr{
				Destination:     "",
				DestinationHash: hash1,
				Port:            8080,
			},
			b: &I2PAddr{
				Destination:     "",
				DestinationHash: hash1,
				Port:            8080,
			},
			want: true,
		},
		{
			name: "different hashes",
			a: &I2PAddr{
				Destination:     "",
				DestinationHash: hash1,
				Port:            8080,
			},
			b: &I2PAddr{
				Destination:     "",
				DestinationHash: hash2,
				Port:            8080,
			},
			want: false,
		},
		{
			name: "same destination but different hashes",
			a: &I2PAddr{
				Destination:     "test.i2p",
				DestinationHash: hash1,
				Port:            8080,
			},
			b: &I2PAddr{
				Destination:     "test.i2p",
				DestinationHash: hash2,
				Port:            8080,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Equal(tt.b); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

// BenchmarkI2PAddr_String benchmarks the String() method.
func BenchmarkI2PAddr_String(b *testing.B) {
	addr := &I2PAddr{
		Destination: "very-long-destination-string-that-exceeds-sixteen-characters-to-test-truncation",
		Port:        8080,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = addr.String()
	}
}

// BenchmarkParseI2PAddr benchmarks address parsing.
func BenchmarkParseI2PAddr(b *testing.B) {
	input := "example.destination.i2p:8080"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseI2PAddr(input)
	}
}
