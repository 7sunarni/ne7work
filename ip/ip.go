package ip

import (
	"fmt"

	"github.com/7sunarni/ne7work/utils"
)

type Header struct {
	HL         byte
	Version    byte
	Tos        byte
	Len        uint16
	Id         uint16
	FragOffset uint16
	TTL        byte
	Proto      byte
	CSum       uint16
	SAddr      [4]byte
	DAddr      [4]byte
	Payload    []byte
}

func (h *Header) String() string {
	template := `
HL: %d
Version: %d
Tos: %d
Len: %d
Id: %d
FragOffset: %d
TTL: %d
Proto: %d
CSum: %d
** SAddr: %s
** DAddr: %s
`
	return fmt.Sprintf(template,
		h.HL,
		h.Version,
		h.Tos,
		h.Len,
		h.Id,
		h.FragOffset,
		h.TTL,
		h.Proto,
		h.CSum,
		utils.IpV4Format(h.SAddr),
		utils.IpV4Format(h.DAddr),
	)
}

func Parse(ip []byte) *Header {
	h := &Header{
		HL:         ip[0] & 0x0f,
		Version:    ip[0] >> 4,
		Tos:        ip[1],
		Len:        uint16(ip[2])<<8 | uint16(ip[3]),
		Id:         uint16(ip[4])<<8 | uint16(ip[5]),
		FragOffset: utils.ByteToUint16(ip[6], ip[7]),
		TTL:        ip[8],
		Proto:      ip[9],
		CSum:       utils.ByteToUint16(ip[10], ip[11]),
		SAddr:      [4]byte{ip[12], ip[13], ip[14], ip[15]},
		DAddr:      [4]byte{ip[16], ip[17], ip[18], ip[19]},
		Payload:    ip[20:],
	}
	return h
}

func (h *Header) Bytes() []byte {
	var bytes []byte
	bytes = append(bytes, (h.Version<<4)|h.HL)
	bytes = append(bytes, h.Tos)
	bytes = append(bytes, utils.Uint16ToBytes(h.Len)...)
	bytes = append(bytes, utils.Uint16ToBytes(h.Id)...)
	bytes = append(bytes, utils.Uint16ToBytes(h.FragOffset)...)
	bytes = append(bytes, h.TTL)
	bytes = append(bytes, h.Proto)
	bytes = append(bytes, utils.Uint16ToBytes(h.CSum)...)
	bytes = append(bytes, h.SAddr[:]...)
	bytes = append(bytes, h.DAddr[:]...)
	bytes = append(bytes, h.Payload...)
	return bytes
}

func (h *Header) Checksum() bool {
	checksum := h.CSum
	payload := h.Payload

	h.CSum = 0
	h.Payload = nil

	b := h.Bytes()
	ret := utils.Checksum(b)

	h.CSum = checksum
	h.Payload = payload
	return ret == checksum
}
