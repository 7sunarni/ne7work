package tcp

import (
	"fmt"
	"log"

	"github.com/7sunarni/ne7work/utils"
)

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
	Options Options
	Data    []byte
}

func (p *Payload) Bytes() []byte {
	ret := make([]byte, 0)
	ret = append(ret, p.Options.Bytes()...)
	ret = append(ret, p.Data...)
	return ret
}

func (h *Header) Bytes() []byte {
	ret := make([]byte, 0)
	ret = append(ret, utils.Uint16ToBytes(h.SPort)...)
	ret = append(ret, utils.Uint16ToBytes(h.DPort)...)
	ret = append(ret, utils.Uint32ToBytes(h.Seq)...)
	ret = append(ret, utils.Uint32ToBytes(h.AckSeq)...)
	// reserved, header length
	ret = append(ret, (h.Reserved << 4))
	// flags
	ret = append(ret, h.Flags)
	// window
	ret = append(ret, utils.Uint16ToBytes(h.Win)...)
	// checksum
	ret = append(ret, utils.Uint16ToBytes(h.CSum)...)
	// urgent pointer
	ret = append(ret, utils.Uint16ToBytes(h.Urp)...)
	ret = append(ret, h.Payload.Bytes()...)
	return ret
}

// todo: use parser to parse header, options, payload
func Parse(data []byte) *Header {
	log.Printf("%x %x", data[16], data[17])
	h := &Header{
		SPort:        uint16(data[0])<<8 | uint16(data[1]),
		DPort:        uint16(data[2])<<8 | uint16(data[3]),
		Seq:          uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		AckSeq:       uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
		Reserved:     data[12] >> 4,
		HeaderLength: data[12] & 0x0f,
		Flags:        data[13],
		Win:          uint16(data[14])<<8 | uint16(data[15]),
		CSum:         utils.ByteToUint16(data[16], data[17]),
		Urp:          uint16(data[18])<<8 | uint16(data[19]),
		Payload:      NewPayloadParser(data[20:]).parse(),
	}
	return h
}

type PayloadParser struct {
	cursor  int
	options Options
	raw     []byte
}

func NewPayloadParser(data []byte) *PayloadParser {
	return &PayloadParser{
		cursor:  0,
		options: make([]Option, 0),
		raw:     data,
	}
}

func (p *PayloadParser) parse() Payload {
	p.ParseOptions()
	return Payload{
		Options: p.options,
		Data:    p.raw[p.cursor:],
	}
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

/*
todo:

https://www.securitynik.com/2015/08/calculating-udp-checksum-with-taste-of_3.html
*/
func (h *Header) Checksum(Sip [4]byte, Dip [4]byte, protocol byte, length uint16) bool {
	pseudoHeader := make([]byte, 0)
	pseudoHeader = append(pseudoHeader, Sip[:]...)
	pseudoHeader = append(pseudoHeader, Dip[:]...)
	pseudoHeader = append(pseudoHeader, byte(0))
	pseudoHeader = append(pseudoHeader, protocol)
	pseudoHeader = append(pseudoHeader, utils.Uint16ToBytes(length)[:]...)

	log.Printf("src: %s:%d dest %s:%d", utils.IpV4Format(Sip), h.SPort, utils.IpV4Format(Dip), h.DPort)

	csum := h.CSum
	h.CSum = 0

	if csum == 0 {
		return true
	}

	log.Printf("after   tcp header: [% x]", h.Bytes())

	end := make([]byte, 0)
	end = append(end, pseudoHeader...)
	end = append(end, h.Bytes()...)
	log.Printf("pseudo header length %d data length %d tcp header length %d data [% x]", length, len(end), h.HeaderLength, end)

	ret := utils.Checksum(end[:])

	log.Printf(`tcp checksum calculated: %d real %d`, ret, csum)

	h.CSum = csum

	return ret == csum
}
