package ip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func checksum(buf []byte) uint16 {
	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	/*
	 * From RFC 768:
	 * If the computed checksum is zero, it is transmitted as all ones (the
	 * equivalent in one's complement arithmetic). An all zero transmitted
	 * checksum value means that the transmitter generated no checksum (for
	 * debugging or for higher level protocols that don't care).
	 */
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

type Version uint8 // should be 4 bit
type HLEN uint8    // should be 4 bit
type TypeOfService uint8
type TotalLength uint16
type Identification uint16
type Flag bool             // 3 Flag bits will be meged with the Fragment offset
type FragmentOffset uint16 // should be 13 bit
type TTL uint8
type Protocol uint8
type HeaderChecksum uint16
type IP uint32
type Option struct {
	Code   uint8
	Length uint8
	Data   []byte
}
type Options []Option

func (i *IP) FromString(s string) error {
	temp := strings.Split(s, ".")
	if len(temp) < 4 {
		return errors.New("invalid ipv4 string")
	}
	// Octets 0xFF FF FF FF
	// oct 1 to 4 from left to right
	num := 0
	oct1, err := strconv.Atoi(temp[0])
	if err != nil {
		return err
	}
	oct2, err := strconv.Atoi(temp[1])
	if err != nil {
		return err
	}
	oct3, err := strconv.Atoi(temp[2])
	if err != nil {
		return err
	}
	oct4, err := strconv.Atoi(temp[3])
	if err != nil {
		return err
	}
	num = (num | oct1) << 24
	num = (num | oct2) << 16
	num = (num | oct3) << 8
	num = (num | oct4)
	*i = IP(num)
	return nil
}

func (i *IP) String() string {
	// Octets 0xFF FF FF FF
	// oct 1 to 4 from left to right
	num := uint32(*i)
	oct1 := num >> 24
	oct2 := (num & 0xFF0000) >> 16
	oct3 := (num & 0xFF00) >> 8
	oct4 := (num & 0xFF)
	return fmt.Sprintf("%d.%d.%d.%d", oct1, oct2, oct3, oct4)
}

func (opt *Option) Len() int {
	return 2 + len(opt.Data)
}

func (opt *Option) MarshalBinary() ([]byte, error) {
	opt.Length = uint8(opt.Len())
	b := make([]byte, opt.Length)
	temp := uint16(opt.Code)<<4 | uint16(opt.Length)
	binary.BigEndian.PutUint16(b[0:2], temp)
	if opt.Length > 2 {
		copy(b[2:opt.Length], opt.Data)
	}
	return []byte{}, nil
}

func (opt *Option) UnmarshalBinary(b []byte) error {
	temp := binary.BigEndian.Uint16(b[0:2])
	opt.Code = uint8(temp >> 8)
	opt.Length = uint8(temp & 0x00FF)
	if opt.Length > 2 {
		copy(opt.Data, b[2:opt.Length])
	}
	return nil
}

func (opts Options) Len() int {
	optsLen := 0
	for _, opt := range opts {
		optsLen += opt.Len()
	}
	return optsLen
}

func (opts Options) MarshalBinary() ([]byte, error) {
	optsLen := opts.Len()
	b := make([]byte, optsLen)
	n := 0
	for _, opt := range opts {
		bopt, err := opt.MarshalBinary()
		if err != nil {
			return b, err
		}
		copy(b[n:opt.Length], bopt)
		n += int(opt.Length)
	}
	return b, nil
}

func (opts Options) UnmarshalBinary(b []byte) error {
	n := 0
	for n < len(opts) {
		opt := Option{}
		err := opt.UnmarshalBinary(b[n:])
		if err != nil {
			return err
		}
		opts = append(opts, opt)
		n += opt.Len()
	}
	return nil
}

const (
	VersionIPv4 Version = 4
)

type IPv4 struct {
	Version        Version
	HLEN           HLEN
	TypeOfService  TypeOfService
	TotalLength    TotalLength
	Identification Identification
	NullFlag       Flag
	DontFragment   Flag
	MoreFragement  Flag
	FragmentOffset FragmentOffset
	TTL            TTL
	Protocol       Protocol
	HeaderChecksum HeaderChecksum
	Source         IP
	Destination    IP
	Options        Options
	Padding        []byte
	Data           []byte
}

func (ip *IPv4) headerLength() uint8 {
	// 20 Bytes + Options Length
	optLen := ip.Options.Len()
	ip.HLEN = (HLEN(optLen) + 20) / 4
	return uint8(ip.HLEN)
}

func (ip *IPv4) totalLength() uint16 {
	totalLen := uint16(ip.headerLength()*4) + uint16(len(ip.Data))
	ip.TotalLength = TotalLength(totalLen)
	return totalLen
}

func (ip *IPv4) getFlags() uint16 {
	var res uint16
	if ip.NullFlag {
		res = res | 4
	}
	if ip.DontFragment {
		res = res | 2
	}
	if ip.MoreFragement {
		res = res | 1
	}
	return res
}

func (ip *IPv4) read(b []byte) (int, error) {
	// Add Version, HLEN, ToS
	temp1 := uint8(ip.Version)<<4 | uint8(ip.HLEN)
	temp := uint16(temp1)<<8 | uint16(ip.TypeOfService)
	binary.BigEndian.PutUint16(b[:2], temp)
	// Add Total Length
	binary.BigEndian.PutUint16(b[2:4], uint16(ip.TotalLength))
	// Add Identification
	binary.BigEndian.PutUint16(b[4:6], uint16(ip.Identification))
	// Add Flags and Offset
	temp2 := ip.getFlags()<<13 | uint16(ip.FragmentOffset)
	binary.BigEndian.PutUint16(b[6:8], temp2)
	// Add TTL and Protocol
	temp3 := uint16(ip.TTL)<<8 | uint16(ip.Protocol)
	binary.BigEndian.PutUint16(b[8:10], temp3)
	// Add Empty Checksum
	binary.BigEndian.PutUint16(b[10:12], uint16(0))
	// Add Source and Destination
	binary.BigEndian.PutUint32(b[12:16], uint32(ip.Source))
	binary.BigEndian.PutUint32(b[16:20], uint32(ip.Destination))
	n := 20
	// Add options
	if len(ip.Options) > 0 {
		bopts, err := ip.Options.MarshalBinary()
		if err != nil {
			return n, err
		}
		copy(b[n:n+len(bopts)], bopts)
		n += len(bopts)
		// Add Padding if any
		optsLen := ip.Options.Len()
		if (20 + optsLen) < len(b) {
			padding := make([]byte, len(b)-20-optsLen)
			copy(b[20+optsLen:ip.HLEN*4], padding)
		}
	}
	// Add Header Checkum
	csum := checksum(b[:n])
	binary.BigEndian.PutUint16(b[10:12], csum)
	// Add Payload
	copy(b[n:], ip.Data)
	return int(ip.totalLength()), nil
}

func (ip *IPv4) MarshalBinary() ([]byte, error) {
	b := make([]byte, ip.totalLength())
	_, err := ip.read(b)
	return b, err
}

func (ip *IPv4) UnmarshalBinary(b []byte) error {
	if len(b) < 20 {
		return errors.New("invalid header length")
	}
	// Decoding first 16 bit word (Version 4 bit, HLEN 4 bit, TOS 8 bit)
	temp1 := binary.BigEndian.Uint16(b[0:2])
	ip.TypeOfService = TypeOfService(temp1 & 0x00FF)
	ip.Version = Version(temp1 >> 12)
	ip.HLEN = HLEN((temp1 >> 8) & 0x0F)

	ip.TotalLength = TotalLength(binary.BigEndian.Uint16(b[2:4]))
	ip.Identification = Identification(binary.BigEndian.Uint16(b[4:6]))

	// Decoding Flags and Fragment Offset
	temp2 := binary.BigEndian.Uint16(b[6:8])
	ip.FragmentOffset = FragmentOffset(temp2 & 0xE0)
	flags := (temp2 >> 13)
	if (flags & 1) == 1 {
		ip.MoreFragement = true
	}
	if (flags & 2) == 2 {
		ip.DontFragment = true
	}
	if (flags & 4) == 4 {
		ip.NullFlag = true
	}

	// Decoding TTL and Protocol
	temp3 := binary.BigEndian.Uint16(b[8:10])
	ip.TTL = TTL((temp3 & 0xFF00) >> 8)
	ip.Protocol = Protocol(temp3 & 0x00FF)

	ip.HeaderChecksum = HeaderChecksum(binary.BigEndian.Uint16(b[10:12]))
	ip.Source = IP(binary.BigEndian.Uint32(b[12:16]))
	ip.Destination = IP(binary.BigEndian.Uint32(b[16:20]))
	if ip.HLEN > 5 {
		ip.Options = Options{}
		optsLen := ip.Options.Len()
		err := ip.Options.UnmarshalBinary(b[20 : 20+optsLen])
		if err != nil {
			return err
		}
		// read padding if any
		if (20 + optsLen) < len(b) {
			padding := make([]byte, len(b)-20-optsLen)
			copy(padding, b[20+optsLen:ip.HLEN*4])
			ip.Padding = padding
		}

	}
	ip.Data = b[ip.HLEN*4:]
	return nil
}
