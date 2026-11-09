package ackhandler

import (
	"slices"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

type congestionEventEx struct {
	acked []congestion.PacketNumber
	lost  []congestion.PacketNumber
}

// recordingCongestionControlEx never limits sending and records every
// extended congestion event it receives.
type recordingCongestionControlEx struct {
	events []congestionEventEx
}

var _ congestion.CongestionControlEx = &recordingCongestionControlEx{}

func (c *recordingCongestionControlEx) SetRTTStatsProvider(congestion.RTTStatsProvider) {}
func (c *recordingCongestionControlEx) TimeUntilSend(congestion.ByteCount) monotime.Time {
	return 0
}
func (c *recordingCongestionControlEx) HasPacingBudget(monotime.Time) bool { return true }
func (c *recordingCongestionControlEx) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}
func (c *recordingCongestionControlEx) CanSend(congestion.ByteCount) bool { return true }
func (c *recordingCongestionControlEx) MaybeExitSlowStart()               {}
func (c *recordingCongestionControlEx) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}

func (c *recordingCongestionControlEx) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}
func (c *recordingCongestionControlEx) OnRetransmissionTimeout(bool)            {}
func (c *recordingCongestionControlEx) SetMaxDatagramSize(congestion.ByteCount) {}
func (c *recordingCongestionControlEx) InSlowStart() bool                       { return false }
func (c *recordingCongestionControlEx) InRecovery() bool                        { return false }
func (c *recordingCongestionControlEx) GetCongestionWindow() congestion.ByteCount {
	return 1 << 20
}

func (c *recordingCongestionControlEx) OnCongestionEventEx(_ congestion.ByteCount, _ monotime.Time, acked []congestion.AckedPacketInfo, lost []congestion.LostPacketInfo) {
	var ev congestionEventEx
	for _, p := range acked {
		ev.acked = append(ev.acked, p.PacketNumber)
	}
	for _, p := range lost {
		ev.lost = append(ev.lost, p.PacketNumber)
	}
	c.events = append(c.events, ev)
}

// Each extended congestion event must report exactly what the triggering ACK
// or loss timer found, and nothing left over from an earlier event.
func TestSentPacketHandlerCongestionEventEx(t *testing.T) {
	rttStats := utils.NewRTTStats()
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		false,
		nil,
		utils.DefaultLogger,
	)
	cc := &recordingCongestionControlEx{}
	sph.SetCongestionControl(cc)

	var packets packetTracker
	sendPacket := func(ti monotime.Time) protocol.PacketNumber {
		t.Helper()
		pn := sph.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}
	ack := func(rcvTime monotime.Time, pns ...protocol.PacketNumber) {
		t.Helper()
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns...)}, protocol.Encryption1RTT, rcvTime)
		require.NoError(t, err)
	}

	const rtt = time.Second
	now := monotime.Now()
	pn1 := sendPacket(now.Add(-rtt))
	pn2 := sendPacket(now.Add(-10 * time.Millisecond))
	pn3 := sendPacket(now)

	// pn1 is lost by time threshold, pn2 is not lost yet
	ack(now.Add(rtt), pn3)
	require.Equal(t, []congestionEventEx{
		{acked: []congestion.PacketNumber{congestion.PacketNumber(pn3)}, lost: []congestion.PacketNumber{congestion.PacketNumber(pn1)}},
	}, cc.events)

	// the loss timer declares pn2 lost
	sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout())
	require.Equal(t, congestionEventEx{lost: []congestion.PacketNumber{congestion.PacketNumber(pn2)}}, cc.events[1])

	// a duplicate ACK acknowledges nothing new and must not report pn2 again
	ack(now.Add(2*rtt), pn3)
	require.Len(t, cc.events, 2)

	pn4 := sendPacket(now.Add(2 * rtt))
	ack(now.Add(3*rtt), pn3, pn4)
	require.Equal(t, congestionEventEx{acked: []congestion.PacketNumber{congestion.PacketNumber(pn4)}}, cc.events[2])
	require.True(t, slices.Contains(packets.Lost, pn2))
}
