package tcp

import (
	"fmt"

	"github.com/7sunarni/ne7work/ip"
	"github.com/7sunarni/ne7work/utils"
)

type TCPState string

var (
	TcpListen      TCPState = "TCP_LISTEN"
	TcpSynSent     TCPState = "TCP_SYN_SENT"
	TcpSynReceived TCPState = "TCP_SYN_RECEIVED"
	TcpEstablished TCPState = "TCP_ESTABLISHED"
	TcpFinWait1    TCPState = "TCP_FIN_WAIT_1"
	TcpFinWait2    TCPState = "TCP_FIN_WAIT_2"
	TcpClose       TCPState = "TCP_CLOSE"
	TcpCloseWait   TCPState = "TCP_CLOSE_WAIT"
	TcpClosing     TCPState = "TCP_CLOSING"
	TcpLastAck     TCPState = "TCP_LAST_ACK"
	TcpTimeWait    TCPState = "TCP_TIME_WAIT"
)

type Manager struct {
	// source-ip:source-port@destination-ip:destination-port to state
	TCPStates map[string]TCPState
}

func init() {
	manager = Manager{
		TCPStates: make(map[string]TCPState),
	}
}

var manager Manager

func getState(ipH ip.Header, h *Header) TCPState {
	key := fmt.Sprintf("%d:%d@%d:%d", utils.BytesToUint32(ipH.SAddr), h.SPort, utils.BytesToUint32(ipH.DAddr), h.DPort)
	state, ok := manager.TCPStates[key]
	if !ok {
		manager.TCPStates[key] = TcpSynReceived
		return TcpSynReceived
	}
	return state
}

func setState(ipH ip.Header, h *Header, state TCPState) {
	key := fmt.Sprintf("%d:%d@%d:%d", utils.BytesToUint32(ipH.SAddr), h.SPort, utils.BytesToUint32(ipH.DAddr), h.DPort)
	manager.TCPStates[key] = state
}

func Handle(ipH ip.Header, h *Header) []byte {
	state := getState(ipH, h)
	switch state {
	case TcpSynReceived:
		return handleReceived(ipH, h)
	}

	return nil
}

func handleReceived(ipH ip.Header, h *Header) []byte {
	ret := h.Reply()
	ret.Flags.Ack = true
	ret.Flags.Syn = true
	checksum := ret.checksum(ipH.DAddr, ipH.SAddr, ipH.Proto, uint16(len(ret.Bytes())))
	ret.CSum = checksum
	return ret.Bytes()
}
