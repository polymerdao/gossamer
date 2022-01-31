// Copyright 2021 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package trie

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ChainSafe/chaindb"
	"github.com/ChainSafe/gossamer/internal/trie/codec"
	"github.com/ChainSafe/gossamer/internal/trie/node"
	"github.com/ChainSafe/gossamer/internal/trie/record"
	"github.com/ChainSafe/gossamer/lib/common"
)

var (
	// ErrEmptyTrieRoot ...
	ErrEmptyTrieRoot = errors.New("provided trie must have a root")

	// ErrValueNotFound ...
	ErrValueNotFound = errors.New("expected value not found in the trie")

	// ErrKeyNotFound ...
	ErrKeyNotFound = errors.New("expected key not found in the trie")

	// ErrKeyFound ...
	ErrKeyFound = errors.New("not expected key found in the trie")

	// ErrDuplicateKeys ...
	ErrDuplicateKeys = errors.New("duplicate keys on verify proof")

	// ErrLoadFromProof ...
	ErrLoadFromProof = errors.New("failed to build the proof trie")

	// ErrInvalidProof ...
	ErrInvalidProof = errors.New("invalid proof")
)

// GenerateProof receive the keys to proof, the trie root and a reference to database
func GenerateProof(root []byte, keys [][]byte, db chaindb.Database) ([][]byte, error) {
	trackedProofs := make(map[string][]byte)

	proofTrie := NewEmptyTrie()
	if err := proofTrie.Load(db, common.BytesToHash(root)); err != nil {
		return nil, err
	}

	for _, k := range keys {
		nk := codec.KeyLEToNibbles(k)

		recorder := record.NewRecorder()
		err := findAndRecord(proofTrie, nk, recorder)
		if err != nil {
			return nil, err
		}

		for _, recNode := range recorder.GetNodes() {
			nodeHashHex := common.BytesToHex(recNode.Hash)
			if _, ok := trackedProofs[nodeHashHex]; !ok {
				trackedProofs[nodeHashHex] = recNode.RawData
			}
		}
	}

	proofs := make([][]byte, 0)
	for _, p := range trackedProofs {
		proofs = append(proofs, p)
	}

	return proofs, nil
}

// Pair holds the key and value to check while verifying the proof
type Pair struct{ Key, Value []byte }

// VerifyProof ensure a given key is inside a proof by creating a proof trie based on the proof slice
// this function ignores the order of proofs
func VerifyProof(proof [][]byte, root []byte, items []Pair) (bool, error) {
	set := make(map[string]struct{}, len(items))

	// check for duplicate keys
	for _, item := range items {
		hexKey := hex.EncodeToString(item.Key)
		if _, ok := set[hexKey]; ok {
			return false, ErrDuplicateKeys
		}
		set[hexKey] = struct{}{}
	}

	proofTrie := NewEmptyTrie()
	if err := proofTrie.loadFromProof(proof, root); err != nil {
		return false, fmt.Errorf("%w: %s", ErrLoadFromProof, err)
	}

	for _, item := range items {
		recValue := proofTrie.Get(item.Key)
		if recValue == nil {
			return false, ErrKeyNotFound
		}
		// here we need to compare value only if the caller pass the value
		if len(item.Value) > 0 && !bytes.Equal(item.Value, recValue) {
			return false, ErrValueNotFound
		}
	}

	return true, nil
}

// VerifyNonExistenceProof ensures a given key does not exist by creating a proof trie based on the proof slice
// and showing that the given key does not exist where it would have been.
// this function ignores the order of proofs
func VerifyNonExistenceProof(proof [][]byte, root []byte, keys [][]byte) (bool, error) {
	set := make(map[string]struct{}, len(keys))

	// check for duplicate keys
	for _, key := range keys {
		hexKey := hex.EncodeToString(key)
		if _, ok := set[hexKey]; ok {
			return false, ErrDuplicateKeys
		}
		set[hexKey] = struct{}{}
	}

	proofTrie := NewEmptyTrie()
	if err := proofTrie.loadFromProof(proof, root); err != nil {
		return false, fmt.Errorf("%w: %s", ErrLoadFromProof, err)
	}

	for _, key := range keys {
		keyNibbles := codec.KeyLEToNibbles(key)
		exists, err := verifyExistence(proofTrie.RootNode(), keyNibbles)
		if err != nil {
			return false, err
		}
		// Fail if key found.
		if exists {
			return false, ErrKeyFound
		}
	}

	return true, nil
}

func verifyExistence(parent Node, key []byte) (bool, error) {
	switch p := parent.(type) {
	case *node.Branch:
		length := lenCommonPrefix(p.Key, key)

		// found value
		if bytes.Equal(p.Key, key) || len(key) == 0 {
			return true, nil
		}

		// did not find value
		if bytes.Equal(p.Key[:length], key) && len(key) < len(p.Key) {
			return false, nil
		}

		// If we're going to a child that should exist, ensure that the child is loaded.
		bitmap := p.ChildrenBitmap()
		childIdx := key[length]
		child := p.Children[childIdx]
		// Child exists in bitmap and should be populated
		if bitmap&(1<<childIdx) > 0 && child == nil {
			return false, ErrInvalidProof
		}
		return verifyExistence(child, key[length+1:])
	case *node.Leaf:
		// found value
		if bytes.Equal(p.Key, key) {
			return true, nil
		}
	case nil:
		// did not find value
		return false, nil
	}
	return false, ErrInvalidProof
}
