// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouprate

import (
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors/program"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "SensorExec")
	os.Exit(ec)
}

type listener struct {
	throttle tetragon.ThrottleType
	cgroup   string
}

func (l *listener) Notify(msg notify.Message) error {
	response := msg.HandleMessage()
	switch response.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessThrottle:
		ev := response.GetProcessThrottle()
		l.throttle = ev.Type
		l.cgroup = ev.Cgroup
	}
	return nil
}

func (l *listener) Close() error {
	return nil
}

type testData struct {
	opts     option.CgroupRate
	value    processapi.CgroupRateValue
	last     uint64
	throttle tetragon.ThrottleType
	ret      bool
}

func TestCheckThrottle(t *testing.T) {
	key := processapi.CgroupRateKey{
		Id: 123,
	}

	rate := cgroupRate{
		key:  key,
		name: "cgroup",
	}

	data := []testData{
		// 0: allowed rate:  10/sec
		//    value.Curr:    11
		//    value.Time:    1 sec
		//    last:          1.001 sec
		//
		//    expected rate: 11 / throttle START
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     11,
				Prev:     0,
				Time:     uint64(time.Second),
				Throttle: 0,
			},
			last: uint64(time.Second) + 1,
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_START,
			ret:      true,
		},
		// 1: allowed rate: 10/sec
		//    value.Curr/Prev:   0
		//    value.Throttle:    1
		//    value.Time:        1 sec
		//    last:              1.001 sec
		//
		//    expected rate:     0 / throttle STOP
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     0,
				Prev:     0,
				Time:     uint64(time.Second),
				Throttle: 1,
			},
			last: uint64(time.Second) + 1,
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_STOP,
			ret:      false,
		},
		// 2: allowed rate:   20/sec
		//    value.Curr:     15
		//    value.Prev:     10
		//    value.Time:     1 sec
		//    last:           1.5 sec
		//
		//    expected rate:  19 / no throttle
		{
			opts: option.CgroupRate{
				Events:   20,
				Interval: uint64(time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     14,
				Prev:     10,
				Time:     uint64(time.Second),
				Throttle: 0,
			},
			last: uint64(time.Second) + 500*uint64(time.Millisecond),
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_UNKNOWN,
			ret:      true,
		},
		// 3: allowed rate:   20/2sec
		//    value.Curr:     21
		//    value.Prev:     0
		//    value.Time:     2 sec
		//    last:           2 sec
		//
		//    expected rate:  21/sec no throttle
		{
			opts: option.CgroupRate{
				Events:   20,
				Interval: uint64(2 * time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     21,
				Prev:     0,
				Time:     uint64(2 * time.Second),
				Throttle: 0,
			},
			last: uint64(2 * time.Second),
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_START,
			ret:      true,
		},
		// 4: allowed rate:   20/2sec
		//    value.Curr:     4
		//    value.Prev:     30
		//    value.Time:     2 sec
		//    last:           3 sec
		//
		//    expected rate:  19 / no throttle
		{
			opts: option.CgroupRate{
				Events:   20,
				Interval: uint64(2 * time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     4,
				Prev:     30,
				Time:     uint64(2 * time.Second),
				Throttle: 0,
			},
			last: uint64(3 * time.Second),
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_UNKNOWN,
			ret:      true,
		},
		// 5: allowed rate:   10/2sec
		//    value.Curr:     10
		//    value.Prev:     20
		//    value.Time:     2 sec
		//    last:           3 sec
		//
		//    expected rate:  20 / throttle START
		{
			opts: option.CgroupRate{
				Events:   20,
				Interval: uint64(2 * time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     10,
				Prev:     20,
				Time:     uint64(2 * time.Second),
				Throttle: 0,
			},
			last: uint64(3 * time.Second),
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_START,
			ret:      true,
		},
		// 6: allowed rate:   20/sec
		//    value.Curr:     0
		//    value.Prev:     20
		//    value.Time:     1 sec
		//    last:           3 sec
		//
		//    expected rate:  0 / no throttle
		{
			opts: option.CgroupRate{
				Events:   20,
				Interval: uint64(time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     0,
				Prev:     20,
				Time:     uint64(time.Second),
				Throttle: 0,
			},
			last: uint64(3 * time.Second),
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_UNKNOWN,
			ret:      false,
		},
		// 7: allowed rate:   10/2sec
		//    value.Curr:     0
		//    value.Prev:     20
		//    value.Time:     1 sec
		//    last:           2 sec
		//
		//    expected rate:  10 / throttle START
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(2 * time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     0,
				Prev:     20,
				Time:     uint64(time.Second),
				Throttle: 0,
			},
			last: uint64(2 * time.Second),
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_START,
			ret:      true,
		},
		// 8: allowed rate:   10/2sec
		//    value.Curr:     0
		//    value.Prev:     20
		//    value.Time:     1 sec
		//    value.Throttle: 1
		//    last:           3 sec
		//
		//    expected rate:  0 / throttle STOP
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(2 * time.Second),
			},
			value: processapi.CgroupRateValue{
				Curr:     0,
				Prev:     20,
				Time:     uint64(time.Second),
				Throttle: 1,
			},
			last: uint64(3 * time.Second),
			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_STOP,
			ret:      false,
		},
	}

	values := make([]processapi.CgroupRateValue, bpf.GetNumPossibleCPUs())

	spec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    uint32(unsafe.Sizeof(key)),
		ValueSize:  uint32(unsafe.Sizeof(values[0])),
		MaxEntries: 32768,
	}

	hash := program.MapBuilder("hash", nil)
	err := hash.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer hash.Close()

	for idx, d := range data {
		h := NewTestCgroupRate(hash, &d.opts)
		l := &listener{}
		h.AddListener(l)

		// store hash values
		values[0] = d.value
		if err := hash.MapHandle.Put(key, values); err != nil {
			t.Fatal("Can't put:", err)
		}

		// skip aliveCnt delay in checkRate
		rate.alive = 0

		t.Logf("Test %d", idx)
		ret := h.checkRate(&rate, d.last)

		assert.Equal(t, d.ret, ret)
		assert.Equal(t, d.throttle, l.throttle)
		if d.throttle != tetragon.ThrottleType_THROTTLE_UNKNOWN {
			assert.Equal(t, "cgroup-123", l.cgroup)
		}
	}
}
