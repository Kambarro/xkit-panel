package api

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// readCPUPct — грубая загрузка CPU по /proc/stat (дельта за 100мс). Linux.
func readCPUPct() float64 {
	idle1, total1 := procStat()
	time.Sleep(100 * time.Millisecond)
	idle2, total2 := procStat()
	dt := total2 - total1
	di := idle2 - idle1
	if dt <= 0 {
		return 0
	}
	return float64(dt-di) / float64(dt) * 100
}

func procStat() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line := strings.Split(string(data), "\n")[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	var vals []uint64
	for _, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		vals = append(vals, v)
		total += v
	}
	if len(vals) >= 4 {
		idle = vals[3]
	}
	return
}