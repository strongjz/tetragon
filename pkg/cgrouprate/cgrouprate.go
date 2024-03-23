// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgrouprate

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
)

const (
	aliveCnt = 5
)

var (
	handle     *CgroupRate
	handleLock sync.RWMutex
)

type Listener interface {
	Notify(msg notify.Message) error
	io.Closer
}

type cgroupRate struct {
	key   processapi.CgroupRateKey
	name  string
	alive int
}

type CgroupRate struct {
	listeners map[Listener]struct{}
	log       logrus.FieldLogger
	ch        chan *cgroupRate
	flag      map[processapi.CgroupRateKey]bool
	flagLock  sync.Mutex
	rates     []*cgroupRate
	opts      *option.CgroupRate
	hash      *program.Map
}

func newCgroupRate(hash *program.Map,
	opts *option.CgroupRate) *CgroupRate {

	if opts.Events == 0 || opts.Interval == 0 {
		logger.GetLogger().Infof("Cgroup rate disabled (opts %d/%d)",
			opts.Events, opts.Interval)
		return nil
	}
	return &CgroupRate{
		listeners: make(map[Listener]struct{}),
		log:       logger.GetLogger(),
		flag:      make(map[processapi.CgroupRateKey]bool),
		ch:        make(chan *cgroupRate),
		hash:      hash,
		opts:      opts,
	}
}

func NewCgroupRate(ctx context.Context,
	hash *program.Map,
	opts *option.CgroupRate) *CgroupRate {

	handleLock.Lock()
	defer handleLock.Unlock()

	handle = newCgroupRate(hash, opts)
	if handle != nil {
		go handle.process(ctx)
	}
	return handle
}

func (r *CgroupRate) AddListener(listener Listener) {
	r.listeners[listener] = struct{}{}
}

func (r *CgroupRate) RemoveListener(listener Listener) {
	delete(r.listeners, listener)
	if err := listener.Close(); err != nil {
		r.log.WithError(err).Warn("failed to close listener")
	}
}

func (r *CgroupRate) Notify(msg notify.Message) {
	for listener := range r.listeners {
		if err := listener.Notify(msg); err != nil {
			r.log.WithError(err).Warn("failed to notify listener")
			r.RemoveListener(listener)
		}
	}
}

func (r *CgroupRate) process(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	r.log.Infof("Cgroup rate started (1s timer, %d/%s)",
		r.opts.Events, time.Duration(r.opts.Interval).String())

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case rate := <-r.ch:
			r.rates = append(r.rates, rate)
		case <-ticker.C:
			r.checkRates()
		}
	}
}

func (r *CgroupRate) checkRates() {
	last, err := ktime.Monotonic()
	if err != nil {
		return
	}

	var tmp []*cgroupRate

	for _, rate := range r.rates {
		if r.checkRate(rate, uint64(last)) {
			tmp = append(tmp, rate)
		}
	}
	r.rates = tmp
}

func (r *CgroupRate) checkRate(rate *cgroupRate, last uint64) bool {
	values := make([]processapi.CgroupRateValue, bpf.GetNumPossibleCPUs())

	if r.hash.MapHandle == nil {
		return true
	}

	hash := r.hash.MapHandle

	if err := hash.Lookup(rate.key, &values); err != nil {
		return false
	}

	// In ebpf code we split the time in interval windows and keep track
	// of events in current (Curr) and previous (Prev) intervals.
	//
	// This function reads this data and computes sliding window rate
	// (Rate) based on current time (Time).
	//
	//                     IntervalStart
	//                     |
	//   |--IntervalLen----|
	//                     |
	//    Prev             | Curr
	//   |-----------------|------------
	//         Rate
	//        |-----------------|
	//                          |
	//                          Time
	//
	// TimeInPrev = IntervalLen - (Time - IntervalStart)
	// Partial    = TimeInPrev / IntervalLen
	// Rate       = Prev x Partial + Curr

	compute := func(v *processapi.CgroupRateValue) uint64 {
		if last > v.Time+uint64(r.opts.Interval) {
			return 0
		}
		slide := r.opts.Interval - (last - v.Time)
		partial := float64(slide) / float64(r.opts.Interval)
		return uint64(float64(v.Prev)*partial) + v.Curr
	}

	var (
		events      uint64
		isThrottled bool
	)

	for _, val := range values {
		events = events + compute(&val)
		isThrottled = isThrottled || val.Throttle != 0
	}

	// We mark cgroup rate values with throttle as true so the
	// ebpf code could skip the event post.
	setThrottle := func(throttle uint64) {
		for idx := range values {
			values[idx].Throttle = throttle
		}
		if err := hash.Update(rate.key, values, 0); err != nil {
			r.log.WithError(err).Warnf("failed to update throttle for cgroup %d",
				rate.key.Id)
		}
	}

	// The cgroup rate is mark as 'not alive' when we see no traffic
	// for more than 5 iterations (atm 5 seconds). The cgroup rate is
	// then removed from the rates list and it's put back on when
	// there's new event on it.
	isAlive := func() bool {
		if events == 0 {
			// Wait for aliveCnt rate loops to make sure the
			// cgroup is silent
			if rate.alive == 0 {
				r.delFlag(rate.key)
				if err := hash.Delete(rate.key); err != nil {
					r.log.WithError(err).Warnf("failed to remove cgroup rate data for cgroup %d",
						rate.key.Id)
				}
				return false
			}
			rate.alive--
		} else if rate.alive < aliveCnt {
			rate.alive = aliveCnt
		}
		return true
	}

	if !isThrottled && events >= r.opts.Events {
		setThrottle(1)
		return true
	}

	if isThrottled && events < r.opts.Events {
		setThrottle(0)
		return isAlive()
	}

	return isAlive()
}

func (r *CgroupRate) addFlag(key processapi.CgroupRateKey) bool {
	r.flagLock.Lock()
	defer r.flagLock.Unlock()

	var ok bool
	if _, ok = r.flag[key]; !ok {
		r.flag[key] = true
	}
	return ok
}

func (r *CgroupRate) delFlag(key processapi.CgroupRateKey) {
	r.flagLock.Lock()
	defer r.flagLock.Unlock()

	delete(r.flag, key)
}

// Called from event handlers to kick off the cgroup rate
// periodical check for event's cgroup.
func Check(kube *processapi.MsgK8s) {
	if handle == nil {
		return
	}

	key := processapi.CgroupRateKey{
		Id: kube.Cgrpid,
	}

	handleLock.RLock()
	defer handleLock.RUnlock()

	// Check if the related cgroup rate is already on the rates
	// list, if not send it through the channel to register it
	if handle == nil || handle.addFlag(key) {
		return
	}

	rate := &cgroupRate{
		key:  key,
		name: string(kube.Docker[:]),
	}

	handle.ch <- rate
}

func Config(optsMap *program.Map) {
	if handle == nil {
		return
	}

	if optsMap.MapHandle == nil {
		handle.log.Warn("failed to update cgroup rate options map")
		return
	}

	key := uint32(0)
	opts := processapi.CgroupRateOptions{
		Interval: handle.opts.Interval,
	}

	if err := optsMap.MapHandle.Put(key, opts); err != nil {
		handle.log.WithError(err).Warn("failed to update cgroup rate options map")
	}
}
