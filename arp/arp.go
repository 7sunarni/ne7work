package arp

import (
	"github.com/7sunarni/ne7work/cons"
	"github.com/7sunarni/ne7work/utils"
)

var ARPETH = utils.ByteToUint16(0x00, 0x01)
var ARPIPV4 = utils.ByteToUint16(0x08, 0x00)

var ARPRequest = utils.ByteToUint16(0x00, 0x01)
var ARPReply = utils.ByteToUint16(0x00, 0x02)

type Header struct {
	HWType    uint16
	ProtoType uint16
	HWSize    byte
	ProSize   byte
	OPCode    uint16
	Payload
}

func Parse(data []byte) *Header {
	if len(data) < 28 {
		return nil
	}
	return &Header{
		HWType:    utils.ByteToUint16(data[0], data[1]),
		ProtoType: utils.ByteToUint16(data[2], data[3]),
		HWSize:    data[4],
		ProSize:   data[5],
		OPCode:    utils.ByteToUint16(data[6], data[7]),
		Payload: Payload{
			SMac: [6]byte{data[8], data[9], data[10], data[11], data[12], data[13]},
			Sip:  [4]byte{data[14], data[15], data[16], data[17]},
			DMac: [6]byte{data[18], data[19], data[20], data[21], data[22], data[23]},
			Dip:  [4]byte{data[24], data[25], data[26], data[27]},
		},
	}
}

func (h *Header) Bytes() []byte {
	ret := make([]byte, 0)
	ret = append(ret, utils.Uint16ToBytes(h.HWType)...)
	ret = append(ret, utils.Uint16ToBytes(h.ProtoType)...)
	ret = append(ret, h.HWSize)
	ret = append(ret, h.ProSize)
	ret = append(ret, utils.Uint16ToBytes(h.OPCode)...)
	ret = append(ret, h.Payload.SMac[:]...)
	ret = append(ret, h.Payload.Sip[:]...)
	ret = append(ret, h.Payload.DMac[:]...)
	ret = append(ret, h.Payload.Dip[:]...)
	return ret
}

type Payload struct {
	SMac [6]byte
	Sip  [4]byte
	DMac [6]byte
	Dip  [4]byte
}

func (h *Header) Reply() *Header {
	arp := &Header{
		HWType:    h.HWType,
		ProtoType: h.ProtoType,
		HWSize:    h.HWSize,
		ProSize:   h.ProSize,
		OPCode:    ARPReply,
		Payload: Payload{
			SMac: cons.DeviceMac,
			Sip:  h.Payload.Dip,
			DMac: h.Payload.SMac,
			Dip:  h.Payload.Sip,
		},
	}
	return arp
}
