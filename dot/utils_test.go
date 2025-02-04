// Copyright 2021 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package dot

import (
	"testing"

	"github.com/ChainSafe/gossamer/lib/genesis"
	"github.com/ChainSafe/gossamer/lib/trie"
	"github.com/stretchr/testify/require"
)

// TestNewConfig tests the NewTestConfig method
func TestNewConfig(t *testing.T) {
	cfg := NewTestConfig(t)
	require.NotNil(t, cfg)
}

// TestNewConfigAndFile tests the NewTestConfigWithFile method
func TestNewConfigAndFile(t *testing.T) {
	testCfg, testCfgFile := newTestConfigWithFile(t)
	require.NotNil(t, testCfg)
	require.NotNil(t, testCfgFile)
}

// TestInitNode
func TestNewTestGenesis(t *testing.T) {
	cfg := NewTestConfig(t)
	require.NotNil(t, cfg)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Init.Genesis = genFile
}

func TestNewTestGenesisFile(t *testing.T) {
	cfg := NewTestConfig(t)
	require.NotNil(t, cfg)

	genHRFile := newTestGenesisFile(t, cfg)

	genRawFile := NewTestGenesisRawFile(t, cfg)

	genHR, err := genesis.NewGenesisFromJSON(genHRFile, 0)
	require.NoError(t, err)
	genRaw, err := genesis.NewGenesisFromJSONRaw(genRawFile)
	require.NoError(t, err)

	// values from raw genesis file should equal values generated from human readable genesis file
	require.Equal(t, genRaw.Genesis.Raw["top"], genHR.Genesis.Raw["top"])
}

func TestTrieSnapshot(t *testing.T) {
	cfg := NewTestConfig(t)
	require.NotNil(t, cfg)

	genRawFile := NewTestGenesisRawFile(t, cfg)

	genRaw, err := genesis.NewGenesisFromJSONRaw(genRawFile)
	require.NoError(t, err)

	tri := trie.NewEmptyTrie()
	key := []byte("key")
	value := []byte("value")

	for k, v := range genRaw.Genesis.Raw["top"] {
		val := []byte(v)
		tri.Put([]byte(k), val)
	}

	dcTrie := tri.DeepCopy()
	require.NoError(t, err)

	// Take Snapshot of the trie.
	newTrie := tri.Snapshot()

	// Get the Trie root hash for all the 3 tries.
	tHash, err := tri.Hash()
	require.NoError(t, err)

	dcTrieHash, err := dcTrie.Hash()
	require.NoError(t, err)

	newTrieHash, err := newTrie.Hash()
	require.NoError(t, err)

	// Root hash for the 3 tries should be equal.
	require.Equal(t, tHash, dcTrieHash)
	require.Equal(t, tHash, newTrieHash)

	// Modify the current trie.
	value[0] = 'w'
	newTrie.Put(key, value)

	// Get the updated root hash of all tries.
	tHash, err = tri.Hash()
	require.NoError(t, err)

	dcTrieHash, err = dcTrie.Hash()
	require.NoError(t, err)

	newTrieHash, err = newTrie.Hash()
	require.NoError(t, err)

	// Only the current trie should have a different root hash since it is updated.
	require.NotEqual(t, newTrieHash, dcTrieHash)
	require.NotEqual(t, newTrieHash, tHash)
	require.Equal(t, dcTrieHash, tHash)
}
