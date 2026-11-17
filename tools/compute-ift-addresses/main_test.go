// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// Expected values were produced by the previous go-ethereum based implementation
// (crypto.HexToECDSA, crypto.PubkeyToAddress, crypto.CreateAddress and Address.Hex).
func TestAddresses(t *testing.T) {
	const anvilKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	cases := []struct {
		key, clientID, prefix, salt string
		nonce                       uint64
		ift, ica                    string
	}{
		{anvilKey, "08-wasm-0", "wf", "salt1", 0, "0x5FbDB2315678afecb367f032d93F642f64180aa3", "wf1ff4wey2e9a4ay9f4y4p7hmtlwx962y594elcf03saqfucgtzjz5sn04an7"},
		{anvilKey, "08-wasm-0", "wf", "salt1", 1, "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512", "wf10t0f59sw8jm0u8ku6q9sd5j5a0dhytjng9f0t2u7s7kce2gn80xs76zc9n"},
		{anvilKey, "08-wasm-0", "wf", "salt1", 18, "0x68B1D87F95878fE05B998F19b66F4baba5De1aed", "wf173l9kyl4dr6h8p3vz4nla9qh5p3ylmrjrvcwyp6apyda0pk80wnqjc9r0d"},
		{anvilKey, "08-wasm-0", "wf", "salt1", 127, "0x5fc748f1FEb28d7b76fa1c6B07D8ba2d5535177c", "wf13mr5zljx5msewmyqqfhyeamxg5jhefwag8txr0xz5ersf2sc6vuqzjpn4p"},
		{anvilKey, "08-wasm-0", "wf", "salt1", 128, "0xB82008565FdC7e44609fA118A4a681E92581e680", "wf14k6g9mmmz5gn2akpx7gsyh9d9hqvmz4hz5h44k0eycncxlp3npzsw8eqjs"},
		{anvilKey, "08-wasm-0", "wf", "salt1", 255, "0x01E21d7B8c39dc4C764c19b308Bd8b14B1ba139E", "wf1rgrlyegqx540f09ak04d9gynycvegsq8pfc7vn2aptvz2rtzufvsnfagx2"},
		{anvilKey, "08-wasm-0", "wf", "salt1", 256, "0x3C1Cb427D20F15563aDa8C249E71db76d7183B6c", "wf13ew9a4r9syazzlas9ywrwuw9v3jagh5639795exd5wu4pj7hrfrspmvtah"},
		{anvilKey, "08-wasm-0", "wf", "salt1", 70000, "0x3808BBF68110240E59B12334b301d8F31ab36363", "wf14ldjff7lxnksqgp6uavw37lkrch2dpv70a9urautuejmwy8syy3sxstan3"},
		{"0000000000000000000000000000000000000000000000000000000000000001", "a", "b", "", 18446744073709551615, "0x9E5805f48a4881E8AB4759d4d3eF77A21DB0eb04", "b13ftjz4zc2jfr73ausjyus4nyhks4re0mdvmnudj35t4afcsrsewqqv5tl2"},
	}
	for _, tc := range cases {
		deployer, err := addressFromPrivateKeyHex(tc.key)
		if err != nil {
			t.Fatal(err)
		}
		ift := checksumHex(createAddress(deployer, tc.nonce))
		if ift != tc.ift {
			t.Errorf("nonce %d: IFT address = %s, want %s", tc.nonce, ift, tc.ift)
		}
		ica, err := computeICAAddress(tc.clientID, ift, tc.salt, tc.prefix)
		if err != nil {
			t.Fatal(err)
		}
		if ica != tc.ica {
			t.Errorf("nonce %d: ICA address = %s, want %s", tc.nonce, ica, tc.ica)
		}
	}
}

func TestInvalidPrivateKeys(t *testing.T) {
	for _, key := range []string{
		"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff",
		"0000000000000000000000000000000000000000000000000000000000000000",
		// secp256k1 group order N
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
	} {
		if _, err := addressFromPrivateKeyHex(key); err == nil {
			t.Errorf("expected error for key %q", key)
		}
	}
}
