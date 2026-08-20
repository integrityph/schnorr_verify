package schnorr_verify

import (
	"math/big"

	"github.com/integrityph/schnorr_verify/secp256"
)

// VerifyBIP340 takes a 32-byte x-only pubkey, a message, and a 64-byte signature.
func VerifyBIP340(pubKeyBytes, msg, sigBytes []byte) bool {
	if len(pubKeyBytes) != 32 || len(sigBytes) != 64 {
		return false
	}

	// curve := btcec.S256()
	curve := secp256.GetCurve()

	// 1. Parse r and s
	rBytes := sigBytes[:32]
	sBytes := sigBytes[32:]
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	// Fail if r >= p or s >= n
	if r.Cmp(curve.P) >= 0 || s.Cmp(curve.N) >= 0 {
		return false
	}

	// 2. Lift X to get the Public Key Point (BIP-340 assumes even Y)
	// Prepending 0x02 treats it as a standard compressed pubkey with an even Y coordinate.
	pkBytes := make([]byte, 33)
	pkBytes[0] = 0x02
	copy(pkBytes[1:], pubKeyBytes)
	pubKey, err := secp256.ParsePubKey(pkBytes)
	if err != nil {
		return false
	}

	// 3. Calculate challenge e = hashBIP0340/challenge( r || pubKeyX || msg ) mod n
	var buf []byte
	buf = append(buf, rBytes...)
	buf = append(buf, pubKeyBytes...)
	buf = append(buf, msg...)

	eBytes := secp256.TaggedHash("BIP0340/challenge", buf)
	e := new(big.Int).SetBytes(eBytes)
	e.Mod(e, curve.N)

	// 4. Calculate R = s*G - e*P
	// To do subtraction, we negate e: e_neg = (n - e) mod n
	eNeg := new(big.Int).Sub(curve.N, e)

	// s*G
	sGx, sGy := curve.ScalarBaseMult(sBytes)

	// e_neg*P (which is -e*P)
	ePx, ePy := curve.ScalarMult(pubKey.X(), pubKey.Y(), eNeg.Bytes())

	// R = s*G + (-e*P)
	Rx, Ry := curve.Add(sGx, sGy, ePx, ePy)

	// 5. Fail if R is the point at infinity (Rx == 0 && Ry == 0)
	if Rx.Sign() == 0 && Ry.Sign() == 0 {
		return false
	}

	// 6. Fail if R's Y-coordinate is odd
	if Ry.Bit(0) == 1 {
		return false
	}

	// 7. Success if R's X-coordinate matches r
	return Rx.Cmp(r) == 0
}

// func main() {
// 	// 1. Generate a valid private key
// 	privKey, err := btcec.NewPrivateKey()
// 	if err != nil {
// 		log.Fatalf("Failed to generate private key: %v", err)
// 	}
// 	pubKey := privKey.PubKey()

// 	// BIP-340 uses 32-byte X-only pubkeys
// 	pubKeyBytes := schnorr.SerializePubKey(pubKey)

// 	// 2. Hash your payload first! (BIP-340 requires a 32-byte message)
// 	rawPayload := []byte("Hello, zero-dependency world!")
// 	msgHash := sha256.Sum256(rawPayload)

// 	// 3. Sign using the official, audited btcsuite implementation
// 	signature, err := schnorr.Sign(privKey, msgHash[:])
// 	if err != nil {
// 		log.Fatalf("Failed to sign: %v", err)
// 	}
// 	sigBytes := signature.Serialize() // Exactly 64 bytes

// 	fmt.Println("--- Test Vectors ---")
// 	fmt.Printf("Message Hash : %x\n", msgHash)
// 	fmt.Printf("Public Key   : %x\n", pubKeyBytes)
// 	fmt.Printf("Signature    : %x\n", sigBytes)
// 	fmt.Println("--------------------")

// 	// ---------------------------------------------------------
// 	// TEST 1: The Happy Path
// 	// ---------------------------------------------------------
// 	isValid := VerifyBIP340(pubKeyBytes, msgHash[:], sigBytes)
// 	fmt.Printf("[Test 1] Valid signature check:\t\t %v (Expected: true)\n", isValid)

// 	// ---------------------------------------------------------
// 	// TEST 2: Tamper with the Message
// 	// ---------------------------------------------------------
// 	badMsgHash := msgHash
// 	badMsgHash[0] ^= 0xFF // Flip bits in the first byte of the hash

// 	isBadMsgValid := VerifyBIP340(pubKeyBytes, badMsgHash[:], sigBytes)
// 	fmt.Printf("[Test 2] Tampered message check:\t %v (Expected: false)\n", isBadMsgValid)

// 	// ---------------------------------------------------------
// 	// TEST 3: Tamper with the Signature
// 	// ---------------------------------------------------------
// 	badSigBytes := make([]byte, 64)
// 	copy(badSigBytes, sigBytes)
// 	badSigBytes[31] ^= 0xFF // Flip bits in the 'r' value of the signature

// 	isBadSigValid := VerifyBIP340(pubKeyBytes, msgHash[:], badSigBytes)
// 	fmt.Printf("[Test 3] Tampered signature check:\t %v (Expected: false)\n", isBadSigValid)
// }
