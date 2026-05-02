package gost

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame is the wire format used by both admin and xor (NOPORT) protocols.
//
//	magic     uint32  // FrameMagic
//	type      uint8   // FrameTypeAdmin / FrameTypeXOR
//	cmd       uint8   // command, see *Cmd* constants
//	stream_id uint32  // multiplex key (admin uses 0 unless command targets a stream)
//	len       uint16  // payload length, big-endian
//	payload   [len]byte
//
// Total fixed header size = FrameHeaderSize (12 bytes), all values are big-endian.
const (
	FrameMagic      uint32 = 0x00003193
	FrameHeaderSize        = 12
	FrameMaxPayload        = 0xFFFF
)

// Frame types.
const (
	FrameTypeAdmin uint8 = 1
	FrameTypeXOR   uint8 = 2
)

// Admin commands.
const (
	AdminCmdOpenStream  uint8 = 1
	AdminCmdNewQueue    uint8 = 2
	AdminCmdPing        uint8 = 3
	AdminCmdPong        uint8 = 4
	AdminCmdCloseStream uint8 = 5
	AdminCmdAuth        uint8 = 6 // first frame: A -> B authentication
	AdminCmdAuthAck     uint8 = 7
)

// XOR commands.
const (
	XORCmdData       uint8 = 0
	XORCmdQueueHello uint8 = 1 // A -> B first frame on a fresh data queue
	XORCmdStreamFin  uint8 = 2
)

// TLV tags used inside admin payloads.
const (
	TLVStreamID uint8 = 0x01
	TLVQueueID  uint8 = 0x02
	TLVProto    uint8 = 0x03
	TLVXORKey   uint8 = 0x04
	TLVDataPort uint8 = 0x05
	TLVUser     uint8 = 0x06
	TLVAuthKey  uint8 = 0x07
	TLVPoolSize uint8 = 0x08
	TLVSrcAddr  uint8 = 0x10
	TLVDstAddr  uint8 = 0x11
	TLVNet      uint8 = 0x12
)

var (
	// ErrBadMagic indicates a frame whose magic number is wrong.
	ErrBadMagic = errors.New("noport: bad frame magic")
	// ErrPayloadTooLarge indicates the payload exceeds 65535 bytes.
	ErrPayloadTooLarge = errors.New("noport: payload too large")
)

// Frame represents a single wire frame.
type Frame struct {
	Type     uint8
	Cmd      uint8
	StreamID uint32
	Payload  []byte
}

// EncodeTo writes the frame to w. It does not buffer.
func (f *Frame) EncodeTo(w io.Writer) error {
	if len(f.Payload) > FrameMaxPayload {
		return ErrPayloadTooLarge
	}
	var hdr [FrameHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], FrameMagic)
	hdr[4] = f.Type
	hdr[5] = f.Cmd
	binary.BigEndian.PutUint32(hdr[6:10], f.StreamID)
	binary.BigEndian.PutUint16(hdr[10:12], uint16(len(f.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads exactly one frame from r. The returned Payload is a
// freshly allocated slice owned by the caller.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	magic := binary.BigEndian.Uint32(hdr[0:4])
	if magic != FrameMagic {
		return nil, fmt.Errorf("%w: 0x%08x", ErrBadMagic, magic)
	}
	f := &Frame{
		Type:     hdr[4],
		Cmd:      hdr[5],
		StreamID: binary.BigEndian.Uint32(hdr[6:10]),
	}
	plen := binary.BigEndian.Uint16(hdr[10:12])
	if plen > 0 {
		f.Payload = make([]byte, plen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// EncodeTLVs encodes a list of (tag, value) TLVs into a single payload.
// Each entry is encoded as: tag(1) | len(2, big-endian) | value[len].
func EncodeTLVs(items ...TLV) ([]byte, error) {
	total := 0
	for _, it := range items {
		if len(it.Value) > 0xFFFF {
			return nil, fmt.Errorf("noport: TLV value for tag 0x%02x too large", it.Tag)
		}
		total += 3 + len(it.Value)
	}
	out := make([]byte, total)
	off := 0
	for _, it := range items {
		out[off] = it.Tag
		binary.BigEndian.PutUint16(out[off+1:off+3], uint16(len(it.Value)))
		copy(out[off+3:], it.Value)
		off += 3 + len(it.Value)
	}
	return out, nil
}

// DecodeTLVs walks the payload and returns a tag->value map. Duplicate tags
// keep the last value seen.
func DecodeTLVs(payload []byte) (map[uint8][]byte, error) {
	out := map[uint8][]byte{}
	for off := 0; off < len(payload); {
		if off+3 > len(payload) {
			return nil, errors.New("noport: truncated TLV header")
		}
		tag := payload[off]
		l := int(binary.BigEndian.Uint16(payload[off+1 : off+3]))
		if off+3+l > len(payload) {
			return nil, errors.New("noport: truncated TLV value")
		}
		v := make([]byte, l)
		copy(v, payload[off+3:off+3+l])
		out[tag] = v
		off += 3 + l
	}
	return out, nil
}

// TLV is a single tag-length-value entry used by EncodeTLVs.
type TLV struct {
	Tag   uint8
	Value []byte
}

// TLVString returns a TLV holding a UTF-8 string.
func TLVString(tag uint8, s string) TLV { return TLV{Tag: tag, Value: []byte(s)} }

// TLVBytes returns a TLV holding raw bytes.
func TLVBytes(tag uint8, v []byte) TLV { return TLV{Tag: tag, Value: v} }

// TLVUint32 returns a TLV holding a 4-byte big-endian unsigned int.
func TLVUint32(tag uint8, v uint32) TLV {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return TLV{Tag: tag, Value: b}
}

// TLVUint16 returns a TLV holding a 2-byte big-endian unsigned int.
func TLVUint16(tag uint8, v uint16) TLV {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return TLV{Tag: tag, Value: b}
}

// LookupUint32 reads a uint32 TLV. Returns 0 if missing.
func LookupUint32(m map[uint8][]byte, tag uint8) uint32 {
	v, ok := m[tag]
	if !ok || len(v) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

// LookupUint16 reads a uint16 TLV. Returns 0 if missing.
func LookupUint16(m map[uint8][]byte, tag uint8) uint16 {
	v, ok := m[tag]
	if !ok || len(v) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}

// LookupString reads a string TLV. Returns "" if missing.
func LookupString(m map[uint8][]byte, tag uint8) string {
	v, ok := m[tag]
	if !ok {
		return ""
	}
	return string(v)
}
