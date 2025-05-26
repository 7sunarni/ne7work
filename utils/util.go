package utils

import (
	"encoding/binary"
	"fmt"
)

func ByteToUint16(data0 byte, data1 byte) uint16 {
	return binary.BigEndian.Uint16([]byte{data0, data1})
}

func Uint16ToBytes(data uint16) []byte {
	return []byte{byte(data >> 8), byte(data & 0xFF)}
}

func IpV4Format(data [4]byte) string {
	template := "%d.%d.%d.%d"
	return fmt.Sprintf(template, data[0], data[1], data[2], data[3])
}

func Checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
		if sum > 0xFFFF {
			sum = (sum >> 16) + (sum & 0xFFFF)
		}
	}
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}
