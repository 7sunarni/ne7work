package eth

import (
	"fmt"
	"log"

	"github.com/7sunarni/ne7work/utils"
)

var ARPType = utils.ByteToUint16(0x08, 0x06)
var IPType = utils.ByteToUint16(0x08, 0x00)

type Header struct {
	DMac    [6]byte
	SMac    [6]byte
	Typ     uint16
	Payload []byte
}

func Parse(data []byte) *Header {
	if len(data) < 14 {
		log.Printf("")
		return nil
	}
	return &Header{
		DMac:    [6]byte{data[0], data[1], data[2], data[3], data[4], data[5]},
		SMac:    [6]byte{data[6], data[7], data[8], data[9], data[10], data[11]},
		Typ:     utils.ByteToUint16(data[12], data[13]),
		Payload: data[14:],
	}
}

func (h *Header) Bytes() []byte {
	ret := make([]byte, 0)
	ret = append(ret, h.DMac[:]...)
	ret = append(ret, h.SMac[:]...)
	ret = append(ret, utils.Uint16ToBytes(h.Typ)...)
	ret = append(ret, h.Payload...)
	return ret
}

func (h *Header) String() string {
	template := `
DMac [% x]
SMac [% x]
Type %d`
	return fmt.Sprintf(template, h.DMac, h.SMac, h.Typ)
}

func (h *Header) IsArp() bool {
	return h.Typ == ARPType
}

func (h *Header) IsIP() bool {
	return h.Typ == IPType
}

func (h *Header) Reply() *Header {
	DMac := h.DMac
	SMac := h.SMac
	return &Header{
		DMac: SMac,
		SMac: DMac,
		Typ:  h.Typ,
	}
}
