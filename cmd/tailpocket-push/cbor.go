package main

import (
	"encoding/binary"
	"errors"
)

// decodeCBOR reads the small subset of CBOR (RFC 8949) that App Attest uses:
// unsigned and negative integers, byte and text strings, arrays, maps with
// text keys, and false, true and null, all with definite lengths. A map
// comes back as map[string]any, an array as []any. Anything else, data
// after the value, or nesting deeper than 8 is an error.
func decodeCBOR(b []byte) (any, error) {
	d := cborDecoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.i != len(d.b) {
		return nil, errCBOR
	}
	return v, nil
}

var errCBOR = errors.New("cbor: malformed or unsupported")

type cborDecoder struct {
	b []byte
	i int
}

func (d *cborDecoder) head() (major byte, arg uint64, err error) {
	if d.i >= len(d.b) {
		return 0, 0, errCBOR
	}
	ib := d.b[d.i]
	d.i++
	major, info := ib>>5, ib&0x1f
	n := 0
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		n = 1
	case info == 25:
		n = 2
	case info == 26:
		n = 4
	case info == 27:
		n = 8
	default:
		return 0, 0, errCBOR // indefinite lengths and reserved values
	}
	if len(d.b)-d.i < n {
		return 0, 0, errCBOR
	}
	var buf [8]byte
	copy(buf[8-n:], d.b[d.i:d.i+n])
	d.i += n
	return major, binary.BigEndian.Uint64(buf[:]), nil
}

func (d *cborDecoder) value(depth int) (any, error) {
	if depth > 8 {
		return nil, errCBOR
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return arg, nil
	case 1:
		if arg >= 1<<63 {
			return nil, errCBOR
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(len(d.b)-d.i) {
			return nil, errCBOR
		}
		s := d.b[d.i : d.i+int(arg)]
		d.i += int(arg)
		if major == 3 {
			return string(s), nil
		}
		return append([]byte(nil), s...), nil
	case 4:
		if arg > uint64(len(d.b)-d.i) { // every item takes at least a byte
			return nil, errCBOR
		}
		out := make([]any, 0, arg)
		for range arg {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > uint64(len(d.b)-d.i)/2 {
			return nil, errCBOR
		}
		out := make(map[string]any, arg)
		for range arg {
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errCBOR
			}
			if _, dup := out[ks]; dup {
				return nil, errCBOR
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out[ks] = v
		}
		return out, nil
	case 7:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
	}
	return nil, errCBOR // tags, floats, undefined
}
