package tcp

import (
	"fmt"
	"log"

	"github.com/7sunarni/ne7work/utils"
)

type Header struct {
	SPort        uint16
	DPort        uint16
	Seq          uint32
	AckSeq       uint32
	Reserved     byte
	HeaderLength byte
	Flags
	Win  uint16
	CSum uint16
	Urp  uint16
	Payload
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
	ret = append(ret, h.Flags.ToByte())
	// window
	ret = append(ret, utils.Uint16ToBytes(h.Win)...)
	// checksum
	ret = append(ret, utils.Uint16ToBytes(h.CSum)...)
	// urgent pointer
	ret = append(ret, utils.Uint16ToBytes(h.Urp)...)
	ret = append(ret, h.Payload.ToBytes()...)
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
		Flags:        parseFlags(data[13]),
		Win:          uint16(data[14])<<8 | uint16(data[15]),
		CSum:         utils.ByteToUint16(data[16], data[17]),
		Urp:          uint16(data[18])<<8 | uint16(data[19]),
		Payload:      NewPayloadParser(data[20:]).parse(),
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

/*
https://www.securitynik.com/2015/08/calculating-udp-checksum-with-taste-of_3.html
*/
func (h *Header) Checksum(Sip [4]byte, Dip [4]byte, protocol byte, length uint16) bool {
	checksum := h.CSum
	h.CSum = 0

	if checksum == 0 {
		return true
	}
	check := make([]byte, 0)
	/*
		pseudo header
		1. source ip (4 bytes)
		2. destination ip (4 bytes)
		3. padding (1 byte) + protocol (1 byte)
		4. ip data length (2 bytes)
	*/
	check = append(check, Sip[:]...)
	check = append(check, Dip[:]...)
	check = append(check, byte(0))
	check = append(check, protocol)
	check = append(check, utils.Uint16ToBytes(length)[:]...)

	check = append(check, h.Bytes()...)
	h.CSum = checksum

	ret := utils.Checksum(check[:])
	return ret == checksum
}
