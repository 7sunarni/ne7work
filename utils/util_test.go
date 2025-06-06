package utils

import (
	"testing"
)

func TestChecks(t *testing.T) {
	testCases := []struct {
		Name    string
		Payload []byte
		Expect  uint16
	}{
		{
			Name: "1",
			Payload: []byte{
				0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
			},
			Expect: ByteToUint16(0xB1, 0xE6),
		},
		{
			Name: "2",
			Payload: []byte{
				0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x3f, 0x06, 0x00, 0x00, 0x48, 0x12, 0x53, 0x4b, 0x0a, 0x0a, 0x82, 0xd4,
			},
			Expect: ByteToUint16(0x13, 0x81),
		},
		{
			Name: "3",
			Payload: []byte{
				0x45, 0x10, 0x00, 0x34, 0xf8, 0x6f, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x0a, 0x82, 0xd4, 0x48, 0x12, 0x53, 0x4b,
			},
			Expect: ByteToUint16(0x1a, 0x09),
		},
		{
			Name: "4",
			Payload: []byte{
				0x45, 0x10, 0x00, 0x3c, 0xeb, 0x68, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x14, 0x00, 0x01, 0x0a, 0x14, 0x00, 0x04,
			},
			Expect: ByteToUint16(0x3b, 0x17),
		},
	}

	for _, testCase := range testCases {
		if Checksum(testCase.Payload) != testCase.Expect {
			t.Fatalf("Checksum %s failed, expected %d, got %d", testCase.Name, testCase.Expect, Checksum(testCase.Payload))
		}
	}
}
