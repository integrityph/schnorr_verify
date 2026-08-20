package schnorr_verify

import (
	"fmt"
	"math/big"
)

const (
	// PubKeyBytesLenCompressed is the number of bytes of a serialized
	// compressed public key.
	PubKeyBytesLenCompressed = 33

	// PubKeyBytesLenUncompressed is the number of bytes of a serialized
	// uncompressed public key.
	PubKeyBytesLenUncompressed = 65

	// PubKeyFormatCompressedEven is the identifier prefix byte for a public key
	// whose Y coordinate is even when serialized in the compressed format per
	// section 2.3.4 of [SEC1](https://secg.org/sec1-v2.pdf#subsubsection.2.3.4).
	PubKeyFormatCompressedEven byte = 0x02

	// PubKeyFormatCompressedOdd is the identifier prefix byte for a public key
	// whose Y coordinate is odd when serialized in the compressed format per
	// section 2.3.4 of [SEC1](https://secg.org/sec1-v2.pdf#subsubsection.2.3.4).
	PubKeyFormatCompressedOdd byte = 0x03

	// PubKeyFormatUncompressed is the identifier prefix byte for a public key
	// when serialized according in the uncompressed format per section 2.3.3 of
	// [SEC1](https://secg.org/sec1-v2.pdf#subsubsection.2.3.3).
	PubKeyFormatUncompressed byte = 0x04

	// PubKeyFormatHybridEven is the identifier prefix byte for a public key
	// whose Y coordinate is even when serialized according to the hybrid format
	// per section 4.3.6 of [ANSI X9.62-1998].
	//
	// NOTE: This format makes little sense in practice an therefore this
	// package will not produce public keys serialized in this format.  However,
	// it will parse them since they exist in the wild.
	PubKeyFormatHybridEven byte = 0x06

	// PubKeyFormatHybridOdd is the identifier prefix byte for a public key
	// whose Y coordingate is odd when serialized according to the hybrid format
	// per section 4.3.6 of [ANSI X9.62-1998].
	//
	// NOTE: This format makes little sense in practice an therefore this
	// package will not produce public keys serialized in this format.  However,
	// it will parse them since they exist in the wild.
	PubKeyFormatHybridOdd byte = 0x07
)

type PublicKey struct {
	x FieldVal
	y FieldVal
}

// X returns the x coordinate of the public key.
func (p *PublicKey) X() *big.Int {
	return new(big.Int).SetBytes(p.x.Bytes()[:])
}

// Y returns the y coordinate of the public key.
func (p *PublicKey) Y() *big.Int {
	return new(big.Int).SetBytes(p.y.Bytes()[:])
}

func ParsePubKey(serialized []byte) (key *PublicKey, err error) {
	var x, y FieldVal
	switch len(serialized) {
	case PubKeyBytesLenUncompressed:
		// Reject unsupported public key formats for the given length.
		format := serialized[0]
		switch format {
		case PubKeyFormatUncompressed:
		case PubKeyFormatHybridEven, PubKeyFormatHybridOdd:
		default:
			str := fmt.Sprintf("invalid public key: unsupported format: %x",
				format)
			return nil, makeError(ErrPubKeyInvalidFormat, str)
		}

		// Parse the x and y coordinates while ensuring that they are in the
		// allowed range.
		if overflow := x.SetByteSlice(serialized[1:33]); overflow {
			str := "invalid public key: x >= field prime"
			return nil, makeError(ErrPubKeyXTooBig, str)
		}
		if overflow := y.SetByteSlice(serialized[33:]); overflow {
			str := "invalid public key: y >= field prime"
			return nil, makeError(ErrPubKeyYTooBig, str)
		}

		// Ensure the oddness of the y coordinate matches the specified format
		// for hybrid public keys.
		if format == PubKeyFormatHybridEven || format == PubKeyFormatHybridOdd {
			wantOddY := format == PubKeyFormatHybridOdd
			if y.IsOdd() != wantOddY {
				str := fmt.Sprintf("invalid public key: y oddness does not "+
					"match specified value of %v", wantOddY)
				return nil, makeError(ErrPubKeyMismatchedOddness, str)
			}
		}

		// Reject public keys that are not on the secp256k1 curve.
		if !isOnCurve(&x, &y) {
			str := fmt.Sprintf("invalid public key: [%v,%v] not on secp256k1 "+
				"curve", x, y)
			return nil, makeError(ErrPubKeyNotOnCurve, str)
		}

	case PubKeyBytesLenCompressed:
		// Reject unsupported public key formats for the given length.
		format := serialized[0]
		switch format {
		case PubKeyFormatCompressedEven, PubKeyFormatCompressedOdd:
		default:
			str := fmt.Sprintf("invalid public key: unsupported format: %x",
				format)
			return nil, makeError(ErrPubKeyInvalidFormat, str)
		}

		// Parse the x coordinate while ensuring that it is in the allowed
		// range.
		if overflow := x.SetByteSlice(serialized[1:33]); overflow {
			str := "invalid public key: x >= field prime"
			return nil, makeError(ErrPubKeyXTooBig, str)
		}

		// Attempt to calculate the y coordinate for the given x coordinate such
		// that the result pair is a point on the secp256k1 curve and the
		// solution with desired oddness is chosen.
		wantOddY := format == PubKeyFormatCompressedOdd
		if !DecompressY(&x, wantOddY, &y) {
			str := fmt.Sprintf("invalid public key: x coordinate %v is not on "+
				"the secp256k1 curve", x)
			return nil, makeError(ErrPubKeyNotOnCurve, str)
		}

	default:
		str := fmt.Sprintf("malformed public key: invalid length: %d",
			len(serialized))
		return nil, makeError(ErrPubKeyInvalidLen, str)
	}

	return NewPublicKey(&x, &y), nil
}

func NewPublicKey(x, y *FieldVal) *PublicKey {
	var pubKey PublicKey
	pubKey.x.Set(x)
	pubKey.y.Set(y)
	return &pubKey
}
