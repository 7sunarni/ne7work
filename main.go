package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/7sunarni/ne7work/arp"
	"github.com/7sunarni/ne7work/cons"
	"github.com/7sunarni/ne7work/eth"
	"github.com/7sunarni/ne7work/ip"
	"github.com/7sunarni/ne7work/tcp"
)

func main() {
	fd, err := allocTap()
	if err != nil {

	}
	log.Printf("fd %v", fd)
	setIfUp()
	setIfRoute()
	setIfAddress()
	for {
		data := make([]byte, 1024)
		n, err := syscall.Read(int(fd.Fd()), data)
		if err != nil {
			log.Printf("Failed to read from TAP device: %v\n", err)
			break
		}
		if n == 0 {
			continue
		}
		data = data[:n]
		ethHeader := eth.Parse(data)
		if ethHeader == nil {
			log.Printf("Failed to parse Ethernet header")
			continue
		}
		if ethHeader.IsArp() {
			arpHeader := arp.Parse(ethHeader.Payload)
			replyEth := ethHeader.Reply()
			replyEth.SMac = cons.DeviceMac
			replyEth.Payload = arpHeader.Reply().Bytes()
			fd.Write(replyEth.Bytes())
		}
		if ethHeader.IsIP() {
			ipHeader := ip.Parse(ethHeader.Payload)
			if !ipHeader.Checksum() {
				log.Printf("ip checksum failed")
				continue
			}
			tcpHeader := tcp.Parse(ipHeader.Payload)
			if tcpHeader == nil {
				log.Printf("tcpHeader is nil")
				continue
			}
			if !reflect.DeepEqual(tcpHeader.Bytes(), ipHeader.Payload) {
				log.Printf(`
tcpHeader.Bytes() [% x] not equal 
ipHeader.Payload [% x]`, tcpHeader.Bytes(), ipHeader.Payload)

				// continue
			}
			tcpHeader.Checksum(ipHeader.SAddr, ipHeader.DAddr, ipHeader.Proto, ipHeader.Len)
		}
	}
}

func allocTap() (*os.File, error) {
	fd, err := os.OpenFile("/dev/net/tap", os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("Failed to open TAP device: %v\n", err)
		return nil, err
	}

	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	copy(ifr.name[:], cons.NicName)
	ifr.flags = syscall.IFF_TAP | syscall.IFF_NO_PI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd.Fd(),
		uintptr(syscall.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)

	if errno != 0 {
		fd.Close()
		log.Printf("Failed to configure TAP device: %v\n", errno)
	}
	// if err = unix.SetNonblock(int(fd.Fd()), true); err != nil {
	// 	unix.Close(int(fd.Fd()))
	// 	log.Printf("Failed to set TAP device to non-blocking: %v\n", err)
	// 	return fd, nil
	// }

	return fd, nil
}

func setIfUp() error {
	err := exec.Command("/usr/bin/ip", "link", "set", "dev", cons.NicName, "up").Run()
	if err != nil {
		log.Printf("Failed to bring up TAP device: %v\n", err)
		return err
	}
	return nil
}

func setIfRoute() error {
	err := exec.Command("/usr/bin/ip", "route", "add", "dev", cons.NicName, cons.TapCIDR).Run()
	if err != nil {
		log.Printf("Failed to add route to TAP device: %v\n", err)
		return err
	}
	return nil
}

func setIfAddress() error {
	err := exec.Command("/usr/bin/ip", "address", "add", "dev", cons.NicName, "local", cons.GatewayIP).Run()
	if err != nil {
		log.Printf("Failed to add address to TAP device: %v\n", err)
		return err
	}
	return nil
}
