package stats

import (
	"sync/atomic"
	"time"
)

// timelineMinutes is how far back the per-minute graph reaches: 24 hours.
const timelineMinutes = 24 * 60

// minuteBucket holds the counts for one minute. minute is the Unix minute
// the counts belong to; a bucket whose minute is not the one asked for is a
// leftover from a day ago and reads as zero.
type minuteBucket struct {
	minute        atomic.Int64
	total         atomic.Int64
	blocked       atomic.Int64
	cached        atomic.Int64
	unresolved    atomic.Int64
	upstreamError atomic.Int64
}

// timeline is the in-memory source of the dashboard's "Queries over time"
// graph: per-minute counts for the last 24 hours, in a ring. It holds counts
// only, never a domain or a client, is never written to disk, and is empty
// after a restart or a purge, so the graph works under every query_log
// setting, "none" included. It is lock-free: each bucket's fields are
// atomic, and the first event of a new minute claims the bucket with a
// compare-and-swap and zeroes it. An event that races that claim at the very
// start of a minute can be lost or zeroed, which a graph tolerates.
type timeline struct {
	buckets [timelineMinutes]minuteBucket
}

// at returns the bucket for the minute of now, claiming and zeroing it when
// it still holds an older minute.
func (t *timeline) at(now time.Time) *minuteBucket {
	m := now.Unix() / 60
	b := &t.buckets[m%timelineMinutes]
	if old := b.minute.Load(); old != m && b.minute.CompareAndSwap(old, m) {
		b.total.Store(0)
		b.blocked.Store(0)
		b.cached.Store(0)
		b.unresolved.Store(0)
		b.upstreamError.Store(0)
	}
	return b
}

// reset empties every bucket. A purge calls it.
func (t *timeline) reset() {
	for i := range t.buckets {
		t.buckets[i].minute.Store(0)
		t.buckets[i].total.Store(0)
		t.buckets[i].blocked.Store(0)
		t.buckets[i].cached.Store(0)
		t.buckets[i].unresolved.Store(0)
		t.buckets[i].upstreamError.Store(0)
	}
}

// TimelineBucket is one point of the graph series: the counts in the bucket
// that starts at Start (Unix seconds). Cached, Unresolved, and UpstreamError
// are subsets of Total, as in querylog.Bucket, whose JSON shape it shares.
type TimelineBucket struct {
	Start         int64 `json:"start"`
	Total         int64 `json:"total"`
	Blocked       int64 `json:"blocked"`
	Cached        int64 `json:"cached"`
	Unresolved    int64 `json:"unresolved"`
	UpstreamError int64 `json:"upstream_error"`
}

// TimelineWindow is the longest window Timeline can serve.
const TimelineWindow = timelineMinutes * time.Minute

// Timeline returns a dense series covering the last window (at most
// TimelineWindow), each bucket wide (a whole number of minutes, at least
// one), oldest first. The last bucket is the current, partial one. Bucket
// starts are aligned to the bucket width, like querylog.History.
func (c *Counter) Timeline(window, bucket time.Duration, now time.Time) []TimelineBucket {
	if window > TimelineWindow {
		window = TimelineWindow
	}
	bm := int64(bucket / time.Minute)
	if bm < 1 {
		bm = 1
	}
	n := int64(window / time.Minute / time.Duration(bm))
	if n < 1 {
		n = 1
	}
	nowMin := now.Unix() / 60
	lastStart := (nowMin / bm) * bm
	firstStart := lastStart - (n-1)*bm
	out := make([]TimelineBucket, 0, n)
	for start := firstStart; start <= lastStart; start += bm {
		tb := TimelineBucket{Start: start * 60}
		for m := start; m < start+bm && m <= nowMin; m++ {
			if nowMin-m >= timelineMinutes {
				continue
			}
			b := &c.timeline.buckets[m%timelineMinutes]
			if b.minute.Load() != m {
				continue
			}
			tb.Total += b.total.Load()
			tb.Blocked += b.blocked.Load()
			tb.Cached += b.cached.Load()
			tb.Unresolved += b.unresolved.Load()
			tb.UpstreamError += b.upstreamError.Load()
		}
		out = append(out, tb)
	}
	return out
}

// ResetTimeline empties the per-minute graph. A purge calls it.
func (c *Counter) ResetTimeline() {
	c.timeline.reset()
}
