# go-merkletree

[![Tag](https://img.shields.io/github/tag/wealdtech/go-merkletree.svg)](https://github.com/wealdtech/go-merkletree/releases/)
[![License](https://img.shields.io/github/license/wealdtech/go-merkletree.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/wealdtech/go-merkletree?status.svg)](https://godoc.org/github.com/wealdtech/go-merkletree)
[![Travis CI](https://img.shields.io/travis/wealdtech/go-merkletree.svg)](https://travis-ci.org/wealdtech/go-merkletree)
[![codecov.io](https://img.shields.io/codecov/c/github/wealdtech/go-merkletree.svg)](https://codecov.io/github/wealdtech/go-merkletree)

Go implementation of a Merkle tree.


## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

`go-merkletree` is a standard Go module which can be installed with:

```sh
go get github.com/wealdtech/go-merkletree
```

## Usage

### Example

```go
package main

import (
	merkletree "github.com/wealdtech/go-merkletree"
)

// Example using the Merkle tree to generate and verify proofs.
func main() {
	// Data for the tree
	data := [][]byte{
		[]byte("Foo"),
		[]byte("Bar"),
		[]byte("Baz"),
	}

	// Create the tree
	tree, err := merkletree.New(data)
	if err != nil {
		panic(err)
	}

	// Fetch the root hash of the tree
	root := tree.Root()

	baz := data[2]
	// Generate a proof for 'Baz'
	proof, err := tree.GenerateProof(baz, 0)
	if err != nil {
		panic(err)
	}

	// Verify the proof for 'Baz'
	verified, err := merkletree.VerifyProof(baz, false, proof, [][]byte{root})
	if err != nil {
		panic(err)
	}
	if !verified {
		panic("failed to verify proof for Baz")
	}
}
```

## Maintainers

Jim McDonald: [@mcdee](https://github.com/mcdee).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/wealdtech/go-merkltree/issues).

## License

[Apache-2.0](LICENSE) © 2019 Weald Technology Trading Ltd
