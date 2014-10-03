// Copyright 2014 The Cockroach Authors.
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
// Author: Spencer Kimball (spencer.kimball@gmail.com)

package storage

import (
	"crypto/md5"
	"testing"
	"time"

	"github.com/cockroachdb/cockroach/proto"
	"github.com/cockroachdb/cockroach/storage/engine"
	"github.com/cockroachdb/cockroach/util/hlc"
)

const (
	maxClockSkew = 250 * time.Millisecond
)

func TestTimestampCache(t *testing.T) {
	manual := hlc.ManualClock(0)
	clock := hlc.NewClock(manual.UnixNano)
	clock.SetMaxDrift(maxClockSkew)
	tc := NewTimestampCache(clock)

	// First simulate a read of just "a" at time 0.
	tc.Add(engine.Key("a"), nil, clock.Now(), proto.NoTxnMD5, true)
	// Although we added "a" at time 0, the internal cache should still
	// be empty because the t=0 < lowWater.
	if tc.cache.Len() > 0 {
		t.Errorf("expected cache to be empty, but contains %d elements", tc.cache.Len())
	}
	// Verify GetMax returns the lowWater mark which is maxClockSkew.
	if rTS, _ := tc.GetMax(engine.Key("a"), nil, proto.NoTxnMD5); rTS.WallTime != maxClockSkew.Nanoseconds() {
		t.Error("expected maxClockSkew for key \"a\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("notincache"), nil, proto.NoTxnMD5); rTS.WallTime != maxClockSkew.Nanoseconds() {
		t.Error("expected maxClockSkew for key \"notincache\"")
	}

	// Advance the clock and verify same low water mark.
	manual = hlc.ManualClock(maxClockSkew.Nanoseconds() + 1)
	if rTS, _ := tc.GetMax(engine.Key("a"), nil, proto.NoTxnMD5); rTS.WallTime != maxClockSkew.Nanoseconds() {
		t.Error("expected maxClockSkew for key \"a\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("notincache"), nil, proto.NoTxnMD5); rTS.WallTime != maxClockSkew.Nanoseconds() {
		t.Error("expected maxClockSkew for key \"notincache\"")
	}

	// Sim a read of "b"-"c" at time maxClockSkew + 1.
	ts := clock.Now()
	tc.Add(engine.Key("b"), engine.Key("c"), ts, proto.NoTxnMD5, true)

	// Verify all permutations of direct and range access.
	if rTS, _ := tc.GetMax(engine.Key("b"), nil, proto.NoTxnMD5); !rTS.Equal(ts) {
		t.Errorf("expected current time for key \"b\"; got %+v", rTS)
	}
	if rTS, _ := tc.GetMax(engine.Key("bb"), nil, proto.NoTxnMD5); !rTS.Equal(ts) {
		t.Error("expected current time for key \"bb\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("c"), nil, proto.NoTxnMD5); rTS.WallTime != maxClockSkew.Nanoseconds() {
		t.Error("expected maxClockSkew for key \"c\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("b"), engine.Key("c"), proto.NoTxnMD5); !rTS.Equal(ts) {
		t.Error("expected current time for key \"b\"-\"c\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("bb"), engine.Key("bz"), proto.NoTxnMD5); !rTS.Equal(ts) {
		t.Error("expected current time for key \"bb\"-\"bz\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("a"), engine.Key("b"), proto.NoTxnMD5); rTS.WallTime != maxClockSkew.Nanoseconds() {
		t.Error("expected maxClockSkew for key \"a\"-\"b\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("a"), engine.Key("bb"), proto.NoTxnMD5); !rTS.Equal(ts) {
		t.Error("expected current time for key \"a\"-\"bb\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("a"), engine.Key("d"), proto.NoTxnMD5); !rTS.Equal(ts) {
		t.Error("expected current time for key \"a\"-\"d\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("bz"), engine.Key("c"), proto.NoTxnMD5); !rTS.Equal(ts) {
		t.Error("expected current time for key \"bz\"-\"c\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("bz"), engine.Key("d"), proto.NoTxnMD5); !rTS.Equal(ts) {
		t.Error("expected current time for key \"bz\"-\"d\"")
	}
	if rTS, _ := tc.GetMax(engine.Key("c"), engine.Key("d"), proto.NoTxnMD5); rTS.WallTime != maxClockSkew.Nanoseconds() {
		t.Error("expected maxClockSkew for key \"c\"-\"d\"")
	}
}

// TestTimestampCacheEviction verifies the eviction of
// timestamp cache entries after minCacheWindow interval.
func TestTimestampCacheEviction(t *testing.T) {
	manual := hlc.ManualClock(0)
	clock := hlc.NewClock(manual.UnixNano)
	clock.SetMaxDrift(maxClockSkew)
	tc := NewTimestampCache(clock)

	// Increment time to the maxClockSkew low water mark + 1.
	manual = hlc.ManualClock(maxClockSkew.Nanoseconds() + 1)
	aTS := clock.Now()
	tc.Add(engine.Key("a"), nil, aTS, proto.NoTxnMD5, true)

	// Increment time by the minCacheWindow and add another key.
	manual = hlc.ManualClock(int64(manual) + minCacheWindow.Nanoseconds())
	tc.Add(engine.Key("b"), nil, clock.Now(), proto.NoTxnMD5, true)

	// Verify looking up key "c" returns the new low water mark ("a"'s timestamp).
	if rTS, _ := tc.GetMax(engine.Key("c"), nil, proto.NoTxnMD5); !rTS.Equal(aTS) {
		t.Errorf("expected low water mark %+v, got %+v", aTS, rTS)
	}
}

// TestTimestampCacheLayeredIntervals verifies the maximum timestamp
// is chosen if previous entries have ranges which are layered over
// each other.
func TestTimestampCacheLayeredIntervals(t *testing.T) {
	manual := hlc.ManualClock(0)
	clock := hlc.NewClock(manual.UnixNano)
	clock.SetMaxDrift(maxClockSkew)
	tc := NewTimestampCache(clock)
	manual = hlc.ManualClock(maxClockSkew.Nanoseconds() + 1)

	adTS := clock.Now()
	tc.Add(engine.Key("a"), engine.Key("d"), adTS, proto.NoTxnMD5, true)

	beTS := clock.Now()
	tc.Add(engine.Key("b"), engine.Key("e"), beTS, proto.NoTxnMD5, true)

	cTS := clock.Now()
	tc.Add(engine.Key("c"), nil, cTS, proto.NoTxnMD5, true)

	// Try different sub ranges.
	if rTS, _ := tc.GetMax(engine.Key("a"), nil, proto.NoTxnMD5); !rTS.Equal(adTS) {
		t.Error("expected \"a\" to have adTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("b"), nil, proto.NoTxnMD5); !rTS.Equal(beTS) {
		t.Error("expected \"b\" to have beTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("c"), nil, proto.NoTxnMD5); !rTS.Equal(cTS) {
		t.Error("expected \"b\" to have cTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("d"), nil, proto.NoTxnMD5); !rTS.Equal(beTS) {
		t.Error("expected \"d\" to have beTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("a"), engine.Key("b"), proto.NoTxnMD5); !rTS.Equal(adTS) {
		t.Error("expected \"a\"-\"b\" to have adTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("a"), engine.Key("c"), proto.NoTxnMD5); !rTS.Equal(beTS) {
		t.Error("expected \"a\"-\"c\" to have beTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("a"), engine.Key("d"), proto.NoTxnMD5); !rTS.Equal(cTS) {
		t.Error("expected \"a\"-\"d\" to have cTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("b"), engine.Key("d"), proto.NoTxnMD5); !rTS.Equal(cTS) {
		t.Error("expected \"b\"-\"d\" to have cTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("c"), engine.Key("d"), proto.NoTxnMD5); !rTS.Equal(cTS) {
		t.Error("expected \"c\"-\"d\" to have cTS timestamp")
	}
	if rTS, _ := tc.GetMax(engine.Key("c0"), engine.Key("d"), proto.NoTxnMD5); !rTS.Equal(beTS) {
		t.Error("expected \"c0\"-\"d\" to have beTS timestamp")
	}
}

func TestTimestampCacheClear(t *testing.T) {
	manual := hlc.ManualClock(0)
	clock := hlc.NewClock(manual.UnixNano)
	clock.SetMaxDrift(maxClockSkew)
	tc := NewTimestampCache(clock)

	// Increment time to the maxClockSkew low water mark + 1.
	manual = hlc.ManualClock(maxClockSkew.Nanoseconds() + 1)
	ts := clock.Now()
	tc.Add(engine.Key("a"), nil, ts, proto.NoTxnMD5, true)

	// Clear the cache, which will reset the low water mark to
	// the current time + maxClockSkew.
	tc.Clear(clock)

	// Fetching any keys should give current time + maxClockSkew
	expTS := clock.Timestamp()
	expTS.WallTime += maxClockSkew.Nanoseconds()
	if rTS, _ := tc.GetMax(engine.Key("a"), nil, proto.NoTxnMD5); !rTS.Equal(expTS) {
		t.Error("expected \"a\" to have cleared timestamp")
	}
}

// TestTimestampCacheWithTxnMD5 verifies that timestamps matching
// a specified MD5 of the txn ID are ignored.
func TestTimestampCacheWithTxnMD5(t *testing.T) {
	manual := hlc.ManualClock(0)
	clock := hlc.NewClock(manual.UnixNano)
	tc := NewTimestampCache(clock)

	// Add non-txn entry at current time.
	ts1 := clock.Now()
	tc.Add(engine.Key("a"), nil, ts1, proto.NoTxnMD5, true)

	// Add two successive txn entries.
	txn1MD5 := md5.Sum([]byte("txn1"))
	txn2MD5 := md5.Sum([]byte("txn2"))
	ts2 := clock.Now()
	tc.Add(engine.Key("a"), nil, ts2, txn1MD5, true)
	ts3 := clock.Now()
	tc.Add(engine.Key("a"), nil, ts3, txn2MD5, true)

	// Fetching with no transaction gets latest value.
	if ts, _ := tc.GetMax(engine.Key("a"), nil, proto.NoTxnMD5); !ts.Equal(ts3) {
		t.Errorf("expected %s; got %s", ts3, ts)
	}
	// Fetching with txn MD5 "1" gets most recent.
	if ts, _ := tc.GetMax(engine.Key("a"), nil, txn1MD5); !ts.Equal(ts3) {
		t.Errorf("expected %s; got %s", ts3, ts)
	}
	// Fetching with txn MD5 "2" skips most recent.
	if ts, _ := tc.GetMax(engine.Key("a"), nil, txn2MD5); !ts.Equal(ts2) {
		t.Errorf("expected %s; got %s", ts2, ts)
	}
}

// TestTimestampCacheReadVsWrite verifies that the timestamp cache
// can differentiate between read and write timestamp.
func TestTimestampCacheReadVsWrite(t *testing.T) {
	manual := hlc.ManualClock(0)
	clock := hlc.NewClock(manual.UnixNano)
	tc := NewTimestampCache(clock)

	// Add read-only non-txn entry at current time.
	ts1 := clock.Now()
	tc.Add(engine.Key("a"), nil, ts1, proto.NoTxnMD5, true)

	// Add two successive txn entries; one read-only and one read-write.
	txn1MD5 := md5.Sum([]byte("txn1"))
	txn2MD5 := md5.Sum([]byte("txn2"))
	ts2 := clock.Now()
	tc.Add(engine.Key("a"), nil, ts2, txn1MD5, true)
	ts3 := clock.Now()
	tc.Add(engine.Key("a"), nil, ts3, txn2MD5, false)

	// Fetching with no transaction gets latest values.
	if rTS, wTS := tc.GetMax(engine.Key("a"), nil, proto.NoTxnMD5); !rTS.Equal(ts2) || !wTS.Equal(ts3) {
		t.Errorf("expected %s %s; got %s %s", ts2, ts3, rTS, wTS)
	}
	// Fetching with txn MD5 "1" gets original for read and most recent for write.
	if rTS, wTS := tc.GetMax(engine.Key("a"), nil, txn1MD5); !rTS.Equal(ts1) || !wTS.Equal(ts3) {
		t.Errorf("expected %s %s; got %s %s", ts1, ts3, rTS, wTS)
	}
	// Fetching with txn MD5 "2" gets ts2 for read and low water mark for write.
	if rTS, wTS := tc.GetMax(engine.Key("a"), nil, txn2MD5); !rTS.Equal(ts2) || !wTS.Equal(tc.lowWater) {
		t.Errorf("expected %s %s; got %s %s", ts2, tc.lowWater, rTS, wTS)
	}
}