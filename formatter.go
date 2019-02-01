// Copyright © 2018, 2019 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkletree

import "fmt"

// Formatter formats a []byte in to a string.
// It is used by DOT() to provide users with the required format for the graphical display of their Merkle trees.
type Formatter interface {
	// Format
	Format([]byte) string
}

// TruncatedHexFormatter shows only the first and last two bytes of the value
type TruncatedHexFormatter struct{}

func (f *TruncatedHexFormatter) Format(data []byte) string {
	return fmt.Sprintf("%4x…%4x", data[0:2], data[len(data)-2:len(data)])
}

// HexFormatter shows the entire value
type HexFormatter struct{}

func (f *HexFormatter) Format(data []byte) string {
	return fmt.Sprintf("%0x", data)
}

// StringFormatter shows the entire value as a string
type StringFormatter struct{}

func (f *StringFormatter) Format(data []byte) string {
	return fmt.Sprintf("%s", string(data))
}
