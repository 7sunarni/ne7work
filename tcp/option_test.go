package tcp

import (
	"testing"
)

/*
req:
0204 0582
0402
080a 4ea1 7be5 0000 0000
01
03 0307

resp:
0204 0514
0402
080a f44f c6b9 4ea1 7be5
01
03 0307
*/

func BytePtr(b byte) *byte {
	return &b
}

func TestParseOptions(t *testing.T) {
	testCases := []struct {
		payload []byte
		expect  Options
	}{
		{
			payload: []byte{0x02, 0x04, 0x05, 0x82, 0x04, 0x02, 0x08, 0x0a, 0x4e, 0xa1, 0x7b, 0xe5, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07},
			expect: []Option{
				{
					Kind: 0x2,
					Len:  BytePtr(0x04),
					Data: []byte{0x05, 0x82},
				},
				{
					Kind: 0x4,
					Len:  BytePtr(0x02),
					Data: []byte{},
				},
				{
					Kind: 0x8,
					Len:  BytePtr(0x0a),
					Data: []byte{0x4e, 0xa1, 0x7b, 0xe5, 0x00, 0x00, 0x00, 0x00},
				},
				{
					Kind: 0x1,
					Len:  nil,
					Data: nil,
				},
				{
					Kind: 0x3,
					Len:  BytePtr(0x03),
					Data: []byte{0x07},
				},
			},
		},
	}
	for _, tc := range testCases {
		got := NewPayloadParser(tc.payload).parse().Options
		if !got.Equal(&tc.expect) {
			t.Errorf("expect %v, got %v", tc.expect, got)
		}
	}
}

func TestOptionReply(t *testing.T) {
	testCases := []struct {
		payload []byte
		expect  Options
	}{
		{
			payload: []byte{0x02, 0x04, 0x05, 0x82, 0x04, 0x02, 0x08, 0x0a, 0x4e, 0xa1, 0x7b, 0xe5, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07},
			expect: []Option{
				{
					Kind: 0x2,
					Len:  BytePtr(0x04),
					Data: []byte{0x05, 0x82},
				},
				{
					Kind: 0x4,
					Len:  BytePtr(0x02),
					Data: []byte{},
				},
				{
					Kind: 0x8,
					Len:  BytePtr(0x0a),
					Data: []byte{0x4e, 0xa1, 0x7b, 0xe5, 0x4e, 0xa1, 0x7b, 0xe5},
				},
				{
					Kind: 0x1,
					Len:  nil,
					Data: nil,
				},
				{
					Kind: 0x3,
					Len:  BytePtr(0x03),
					Data: []byte{0x07},
				},
			},
		},
	}
	for _, tc := range testCases {
		options := NewPayloadParser(tc.payload).parse().Options
		if !options.Reply().Equal(&tc.expect) {
			t.Errorf("expect %v, got %v", tc.expect, options.Reply())
		}
	}
}
