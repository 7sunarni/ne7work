package tcp

import "fmt"

/*
fin : 1,
syn : 1,
rst : 1,
psh : 1,
ack : 1,
urg : 1,
ece : 1,
cwr : 1;
*/
type Header struct {
	SPort        uint16
	DPort        uint16
	Seq          uint32
	AckSeq       uint32
	Reserved     byte
	HeaderLength byte
	Flags        byte

	Win  uint16
	CSum uint16
	Urp  uint16
	Payload
}

type Payload struct {
	Options []Option
	Data    []byte
}

func Parse(data []byte) *Header {
	h := &Header{
		SPort:        uint16(data[0])<<8 | uint16(data[1]),
		DPort:        uint16(data[2])<<8 | uint16(data[3]),
		Seq:          uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		AckSeq:       uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
		Reserved:     data[12] >> 4,
		HeaderLength: data[12] & 0x0f,
		Flags:        data[13],
		Win:          uint16(data[14])<<8 | uint16(data[15]),
		CSum:         uint16(data[16])<<8 | uint16(data[17]),
		Urp:          uint16(data[18])<<8 | uint16(data[19]),
	}
	return h
}

func (h *Header) String() string {
	template := `
SPort: %d
DPort: %d
Seq: %d
AckSeq: %d
`
	return fmt.Sprintf(template, h.SPort, h.DPort, h.Seq, h.AckSeq)
}
