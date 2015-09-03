// Copyright 2015 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License. See the AUTHORS file
// for names of contributors.
//
// Author: Bram Gruneir (bram+code@cockroachlabs.com)

package main

import (
	"sync"

	"github.com/cockroachdb/cockroach/proto"
)

const (
	bytesPerRange    = 64 * (int64(1) << 20) // 64 MiB
	capacityPerStore = int64(1) << 40        // 1 TiB - 32768 ranges per store
)

type store struct {
	sync.RWMutex
	desc   proto.StoreDescriptor
	ranges []*rng
}

func newStore(storeID proto.StoreID, nodeDesc proto.NodeDescriptor) *store {
	return &store{
		desc: proto.StoreDescriptor{
			StoreID: storeID,
			Node:    nodeDesc,
		},
	}
}

func (s *store) getDesc() proto.StoreDescriptor {
	s.RLock()
	defer s.RUnlock()
	desc := s.desc
	desc.Capacity = s.getCapacity()
	return desc
}

func (s *store) getCapacity() proto.StoreCapacity {
	s.RLock()
	defer s.RUnlock()
	return proto.StoreCapacity{
		Capacity:   capacityPerStore,
		Available:  capacityPerStore - int64(len(s.ranges))*bytesPerRange,
		RangeCount: int32(len(s.ranges)),
	}
}
