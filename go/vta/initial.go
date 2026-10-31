// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vta

import (
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// calleesFunc abstracts call graph in one direction,
// from call sites to callees.
type calleesFunc func(ssa.CallInstruction) []*ssa.Function

// makeCalleesFunc returns the initial call graph for vta as a calleesFunc.
//
// Fork note: upstream falls back to chautil.LazyCallees when c is nil. That
// branch is removed here. rpcshield always seeds VTA with a reflection-aware
// RTA call graph (see rpcshield/rta/vta); a CHA seed would be both less
// precise and unsound with respect to reflection. Requiring a non-nil seed
// makes that a compile-time property rather than a convention. It also drops
// a dependency on golang.org/x/tools/go/callgraph/internal/chautil, which is
// not importable from outside x/tools.
func makeCalleesFunc(c *callgraph.Graph) calleesFunc {
	return func(call ssa.CallInstruction) []*ssa.Function {
		node := c.Nodes[call.Parent()]
		if node == nil {
			return nil
		}
		var cs []*ssa.Function
		for _, edge := range node.Out {
			if edge.Site == call {
				cs = append(cs, edge.Callee.Func)
			}
		}
		return cs
	}
}
