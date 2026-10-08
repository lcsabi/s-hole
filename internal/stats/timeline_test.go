package stats

import (
	"sync"
	"testing"
	"time"
)

func TestRecordQuery_EmptyClientOrDomainIsNotTallied(t *testing.T) {
	// S1: an empty client or domain is not tallied, and the counters still
	// count the query.
	c := New()
	c.SetQueryLogMode("all")
	c.RecordQuery("", "ads.example.com.", true)
	c.RecordQuery("192.168.1.5", "", true)
	c.RecordQuery("", "", true)
	c.RecordQuery("", "", false)
	s := c.Snapshot(10)
	if s.TotalQueries != 4 || s.BlockedCount != 3 {
		t.Errorf("total %d, blocked %d; want 4, 3", s.TotalQueries, s.BlockedCount)
	}
	if len(s.TopClients) != 1 || s.TopClients[0] != (Entry{Name: "192.168.1.5", Count: 1}) {
		t.Errorf("top clients = %v, want only 192.168.1.5 once", s.TopClients)
	}
	if len(s.TopDomains) != 1 || s.TopDomains[0] != (Entry{Name: "ads.example.com.", Count: 1}) {
		t.Errorf("top domains = %v, want only ads.example.com. once", s.TopDomains)
	}
}

func TestResetTallies(t *testing.T) {
	// S1: ResetTallies empties Top Domains and Top Clients and keeps every
	// counter.
	c := New()
	c.SetQueryLogMode("all")
	c.RecordQuery("192.168.1.5", "ads.example.com.", true)
	c.RecordQuery("192.168.1.6", "ok.example.com.", false)
	c.RecordCacheHit()
	c.RecordQuery("192.168.1.6", "ptr.arpa.", false)
	c.RecordLocalPTR()
	c.RecordQuery("192.168.1.6", "dead.example.", false)
	c.RecordForwardFailure()
	c.RecordQuery("192.168.1.6", "bad.example.", false)
	c.RecordUpstreamError()
	before := c.Snapshot(10)

	c.ResetTallies()

	after := c.Snapshot(10)
	if len(after.TopDomains) != 0 || len(after.TopClients) != 0 {
		t.Errorf("after ResetTallies: top domains %v, top clients %v; want both empty", after.TopDomains, after.TopClients)
	}
	if after.TotalQueries != before.TotalQueries || after.BlockedCount != before.BlockedCount ||
		after.CacheHits != before.CacheHits || after.LocalPTRCount != before.LocalPTRCount ||
		after.ForwardFailures != before.ForwardFailures || after.UpstreamErrors != before.UpstreamErrors {
		t.Errorf("counters changed: before %+v, after %+v", before, after)
	}
	if after.TotalQueries != 5 {
		t.Errorf("total = %d, want 5", after.TotalQueries)
	}
	// The tallies work again after the reset.
	c.RecordQuery("192.168.1.7", "new.example.", true)
	if s := c.Snapshot(10); len(s.TopClients) != 1 || len(s.TopDomains) != 1 {
		t.Errorf("after a new query: top clients %v, top domains %v; want one each", s.TopClients, s.TopDomains)
	}
}

// fixedMinute is a time 30 s into a Unix minute that is a multiple of 2880
// (two days) plus offset minutes, so tests know where bucket edges fall.
func fixedMinute(offset int64) time.Time {
	const base = 2880 * 10000 // a Unix minute in 2024
	return time.Unix((base+offset)*60+30, 0).UTC()
}

func sumTimeline(series []TimelineBucket) TimelineBucket {
	var s TimelineBucket
	for _, b := range series {
		s.Total += b.Total
		s.Blocked += b.Blocked
		s.Cached += b.Cached
		s.Unresolved += b.Unresolved
		s.UpstreamError += b.UpstreamError
	}
	return s
}

func TestTimeline_RecordersFillTheCurrentMinute(t *testing.T) {
	// S2: RecordQuery, RecordCacheHit, RecordForwardFailure, and
	// RecordUpstreamError add to the current minute.
	c := New()
	c.SetQueryLogMode("all")
	c.RecordQuery("", "", true)
	c.RecordQuery("", "", true)
	c.RecordQuery("", "", false)
	c.RecordCacheHit()
	c.RecordQuery("", "", false)
	c.RecordForwardFailure()
	c.RecordQuery("", "", false)
	c.RecordUpstreamError()
	now := time.Now()
	series := c.Timeline(time.Hour, time.Minute, now)
	if len(series) != 60 {
		t.Fatalf("series has %d buckets, want 60", len(series))
	}
	want := TimelineBucket{Total: 5, Blocked: 2, Cached: 1, Unresolved: 1, UpstreamError: 1}
	got := sumTimeline(series)
	got.Start = 0
	if got != want {
		t.Errorf("counts in the last hour = %+v, want %+v", got, want)
	}
	// The events are in the last bucket, or in the one before if the minute
	// changed while the test ran.
	tail := sumTimeline(series[len(series)-2:])
	tail.Start = 0
	if tail != want {
		t.Errorf("counts in the last two minutes = %+v, want %+v", tail, want)
	}
}

func TestTimeline_DenseAlignedOldestFirst(t *testing.T) {
	// S2: Timeline returns a dense series, oldest first, with bucket starts
	// aligned to the bucket width, and the current, partial bucket last.
	c := New()
	c.SetQueryLogMode("all")
	now := fixedMinute(37) // 37 minutes past a 2-day boundary
	nowMin := now.Unix() / 60
	put := func(minutesAgo int64, n int64) {
		b := c.timeline.at(time.Unix((nowMin-minutesAgo)*60+5, 0))
		b.total.Add(n)
		b.blocked.Add(1)
	}
	put(0, 1)  // current minute
	put(1, 2)  // one minute ago
	put(7, 4)  // in the 5-minute bucket before the current one
	put(59, 8) // the oldest minute of a 1h window of 1m buckets
	put(60, 16)

	cases := []struct {
		name      string
		window    time.Duration
		bucket    time.Duration
		n         int
		widthMins int64
	}{
		{"1h of 1m", time.Hour, time.Minute, 60, 1},
		{"1h of 5m", time.Hour, 5 * time.Minute, 12, 5},
		{"1h of 30s reads as 1m", time.Hour, 30 * time.Second, 60, 1},
		{"1h of 0 reads as 1m", time.Hour, 0, 60, 1},
		{"48h of 1h is capped at 24h", 48 * time.Hour, time.Hour, 24, 60},
		{"24h of 1h", 24 * time.Hour, time.Hour, 24, 60},
		{"window below the bucket", time.Minute, time.Hour, 1, 60},
		{"zero window", 0, time.Minute, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			series := c.Timeline(tc.window, tc.bucket, now)
			if len(series) != tc.n {
				t.Fatalf("got %d buckets, want %d", len(series), tc.n)
			}
			width := tc.widthMins * 60
			lastStart := (nowMin / tc.widthMins) * tc.widthMins * 60
			if series[len(series)-1].Start != lastStart {
				t.Errorf("last bucket starts at %d, want %d (the current, aligned bucket)", series[len(series)-1].Start, lastStart)
			}
			for i, b := range series {
				if b.Start%width != 0 {
					t.Errorf("bucket %d starts at %d, not aligned to %d s", i, b.Start, width)
				}
				if i > 0 && b.Start-series[i-1].Start != width {
					t.Errorf("bucket %d starts %d s after the previous, want %d", i, b.Start-series[i-1].Start, width)
				}
			}
		})
	}

	// Each count lands in the bucket that holds its minute.
	oneMin := c.Timeline(time.Hour, time.Minute, now)
	wantAt := map[int]int64{59: 1, 58: 2, 52: 4, 0: 8}
	for i, b := range oneMin {
		if b.Total != wantAt[i] {
			t.Errorf("1m bucket %d (%d min ago) total = %d, want %d", i, 59-i, b.Total, wantAt[i])
		}
	}
	fiveMin := c.Timeline(time.Hour, 5*time.Minute, now)
	// The current minute is 37 past a 5-minute edge, so the current bucket
	// holds minutes 35 to 37: the counts from 0 and 1 minute ago (3). The
	// count from 7 minutes ago (minute 30) is in the bucket before it. The 12
	// buckets reach back 57 minutes, so the counts from 59 and 60 minutes ago
	// are outside.
	if got := fiveMin[11].Total; got != 3 {
		t.Errorf("current 5m bucket total = %d, want 3", got)
	}
	if got := fiveMin[10].Total; got != 4 {
		t.Errorf("previous 5m bucket total = %d, want 4", got)
	}
	if got := sumTimeline(fiveMin).Total; got != 7 {
		t.Errorf("5m series total = %d, want 7", got)
	}
}

func TestTimeline_OlderThanADayReadsAsZero(t *testing.T) {
	// S2: a minute older than 24 hours reads as zero. Its ring slot is reused
	// a day later, and a bucket wider than the window does not reach back
	// past 24 hours either.
	c := New()
	c.SetQueryLogMode("all")
	old := fixedMinute(200)
	c.timeline.at(old).total.Add(5)

	// 24 hours and one minute later, the slot of "one minute ago" still holds
	// the old minute.
	later := old.Add(24*time.Hour + time.Minute)
	if got := sumTimeline(c.Timeline(24*time.Hour, time.Minute, later)).Total; got != 0 {
		t.Errorf("a day-old count shows in the series: total = %d, want 0", got)
	}
	// 30 hours later, a 48h bucket starts at the 2-day edge and covers the old
	// minute's time, but the old minute is more than 24 hours back.
	later = old.Add(30 * time.Hour)
	series := c.Timeline(24*time.Hour, 48*time.Hour, later)
	if len(series) != 1 || series[0].Total != 0 {
		t.Errorf("series = %+v, want one bucket with total 0", series)
	}
	// Inside the day, the same count shows.
	if got := sumTimeline(c.Timeline(24*time.Hour, time.Hour, old.Add(time.Hour))).Total; got != 5 {
		t.Errorf("total an hour later = %d, want 5", got)
	}
}

func TestTimeline_NewMinuteClearsTheSlot(t *testing.T) {
	// S2: the first event of a minute claims its ring slot and clears the
	// counts that a minute a day earlier left there.
	c := New()
	c.SetQueryLogMode("all")
	old := fixedMinute(300)
	b := c.timeline.at(old)
	b.total.Add(9)
	b.blocked.Add(9)
	b.cached.Add(9)
	b.unresolved.Add(9)
	b.upstreamError.Add(9)
	day := old.Add(24 * time.Hour)
	c.timeline.at(day).total.Add(1)
	got := c.Timeline(time.Minute, time.Minute, day)
	want := TimelineBucket{Start: (day.Unix() / 60) * 60, Total: 1}
	if len(got) != 1 || got[0] != want {
		t.Errorf("series = %+v, want [%+v]", got, want)
	}
}

func TestResetTimeline(t *testing.T) {
	// S2: ResetTimeline empties the graph and keeps the counters.
	c := New()
	c.SetQueryLogMode("all")
	for i := 0; i < 3; i++ {
		c.RecordQuery("", "", true)
		c.RecordCacheHit()
		c.RecordForwardFailure()
		c.RecordUpstreamError()
	}
	c.timeline.at(time.Now().Add(-3 * time.Hour)).total.Add(7)
	c.ResetTimeline()
	if got := sumTimeline(c.Timeline(24*time.Hour, time.Minute, time.Now())); got != (TimelineBucket{}) {
		t.Errorf("series after ResetTimeline sums to %+v, want zero", got)
	}
	if s := c.Snapshot(0); s.TotalQueries != 3 || s.BlockedCount != 3 || s.CacheHits != 3 {
		t.Errorf("counters after ResetTimeline = %+v, want them kept", s)
	}
	c.RecordQuery("", "", false)
	if got := sumTimeline(c.Timeline(time.Hour, time.Minute, time.Now())).Total; got != 1 {
		t.Errorf("total after a new query = %d, want 1", got)
	}
}

func TestTimeline_ConcurrentRecordAndRead(t *testing.T) {
	// The timeline is lock-free: recording and reading at once must be free of
	// data races (run with -race) and must not lose the count of a minute
	// that is not changing.
	c := New()
	c.SetQueryLogMode("all")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				c.Timeline(time.Hour, time.Minute, time.Now())
			}
		}
	}()
	const per = 500
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				c.RecordQuery("", "", i%2 == 0)
				c.RecordCacheHit()
			}
		}()
	}
	// Let the writers finish, then stop the reader.
	for c.total.Load() < 4*per {
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	got := sumTimeline(c.Timeline(time.Hour, time.Minute, time.Now()))
	// A count can be lost only when a new minute starts during the run.
	if got.Total > 4*per || got.Cached > 4*per {
		t.Errorf("series = %+v, more than the %d queries recorded", got, 4*per)
	}
}
