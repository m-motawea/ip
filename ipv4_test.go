package ip

import (
	"bytes"
	"log"
	"testing"
)

func TestIPv4(t *testing.T) {
	packet := []byte{0x45, 0x00, 0x00, 0x54, 0xf5, 0x7f, 0x40, 0x00, 0x40, 0x01, 0x73, 0x69, 0xc0, 0xa8, 0x01, 0x08,
		0x08, 0x08, 0x08, 0x08,
		0x08, 0x00, 0x5a, 0x08, 0x00, 0x02, 0x00, 0x03, 0x6d, 0xa4, 0xca, 0x5e, 0x00, 0x00, 0x00, 0x00,
		0xa5, 0x1c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	}
	ip := IPv4{}
	ip.UnmarshalBinary(packet)
	log.Printf("%+v", ip)
	res, err := ip.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to Marshal IP due to error %v", err)
	}
	log.Printf("result: %+v", ip)
	if !bytes.Equal(res, packet) {
		t.Errorf("result is not correct\n marshal result:\n%v\nactual:\n%v\n", res, packet)
	}
	log.Printf("SRC IP: %s", ip.Source.String())
	log.Printf("DST IP: %s", ip.Destination.String())

	ip2 := IP(0)
	ip2.FromString("10.10.0.50")
	log.Printf("IP: %s", ip2.String())
}
