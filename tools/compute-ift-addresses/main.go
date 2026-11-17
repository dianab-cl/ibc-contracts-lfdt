// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

const (
	// gmpAccountsKey is the module key used by ibc-go's GMP module to derive interchain account addresses.
	// Formula: SHA256(SHA256("module") + gmpAccountsKey + 0x00 + derivationKey)
	gmpAccountsKey = "gmp-accounts"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <private-key-hex> <nonce> <client-id> <bech32-prefix> [salt]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 18 08-wasm-0 wf\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nComputes the IFT contract address and its corresponding ICA address.\n")
		os.Exit(1)
	}

	privateKeyHex := os.Args[1]
	nonce, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing nonce: %v\n", err)
		os.Exit(1)
	}
	clientID := os.Args[3]
	bech32Prefix := os.Args[4]
	salt := ""
	if len(os.Args) > 5 {
		salt = os.Args[5]
	}

	// Compute IFT address from private key + nonce
	deployer, err := addressFromPrivateKeyHex(privateKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
		os.Exit(1)
	}
	iftAddress := checksumHex(createAddress(deployer, nonce))

	// Compute ICA address from client ID + IFT address + salt
	icaAddress, err := computeICAAddress(clientID, iftAddress, salt, bech32Prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error computing ICA address: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("IFT Address: %s\n", iftAddress)
	fmt.Printf("ICA Address: %s\n", icaAddress)
}

func keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// addressFromPrivateKeyHex returns the Ethereum address of a hex-encoded secp256k1 private key.
func addressFromPrivateKeyHex(privateKeyHex string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid length, need 256 bits")
	}
	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetByteSlice(keyBytes); overflow || scalar.IsZero() {
		return nil, errors.New("invalid private key, must be in range [1, N-1]")
	}
	pubKey := secp256k1.NewPrivateKey(&scalar).PubKey().SerializeUncompressed()
	// The address is the last 20 bytes of the hash of the public key, without the 0x04 prefix.
	return keccak256(pubKey[1:])[12:], nil
}

// createAddress returns the address of a contract deployed with CREATE by sender at nonce:
// the last 20 bytes of keccak256(rlp([sender, nonce])).
func createAddress(sender []byte, nonce uint64) []byte {
	encodedNonce := []byte{0x80} // RLP encoding of 0 (empty string)
	if nonce > 0 {
		nonceBytes := new(big.Int).SetUint64(nonce).Bytes()
		if len(nonceBytes) == 1 && nonceBytes[0] < 0x80 {
			encodedNonce = nonceBytes
		} else {
			encodedNonce = append([]byte{0x80 + byte(len(nonceBytes))}, nonceBytes...)
		}
	}
	// 20-byte sender string plus nonce; always shorter than 56 bytes, so a short list.
	payloadLen := 1 + len(sender) + len(encodedNonce)
	return keccak256([]byte{0xc0 + byte(payloadLen), 0x80 + byte(len(sender))}, sender, encodedNonce)[12:]
}

// checksumHex returns the EIP-55 mixed-case checksum encoding of address, with 0x prefix.
func checksumHex(address []byte) string {
	lower := []byte(hex.EncodeToString(address))
	hash := keccak256(lower)
	for i, c := range lower {
		// Uppercase a letter if the matching nibble of the hash is >= 8.
		nibble := hash[i/2]
		if i%2 == 0 {
			nibble >>= 4
		}
		if c >= 'a' && nibble&0xf >= 8 {
			lower[i] = c - 'a' + 'A'
		}
	}
	return "0x" + string(lower)
}

func computeICAAddress(clientID, sender, salt, bech32Prefix string) (string, error) {
	key := buildKey(clientID, sender, salt)
	combined := append([]byte(gmpAccountsKey), 0x00)
	combined = append(combined, key...)
	moduleHash := sha256.Sum256([]byte("module"))
	finalInput := append(moduleHash[:], combined...)
	addrHash := sha256.Sum256(finalInput)
	addr := addrHash[:]
	return bech32.ConvertAndEncode(bech32Prefix, addr)
}

func buildKey(clientID, sender, salt string) []byte {
	clientIDBytes := []byte(clientID)
	senderBytes := []byte(sender)
	saltBytes := []byte(salt)
	size := 8 + len(clientIDBytes) + 8 + len(senderBytes) + 8 + len(saltBytes)
	key := make([]byte, 0, size)
	key = appendLengthPrefixed(key, clientIDBytes)
	key = appendLengthPrefixed(key, senderBytes)
	key = appendLengthPrefixed(key, saltBytes)
	return key
}

func appendLengthPrefixed(dst, data []byte) []byte {
	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(data)))
	dst = append(dst, lenBuf...)
	dst = append(dst, data...)
	return dst
}
