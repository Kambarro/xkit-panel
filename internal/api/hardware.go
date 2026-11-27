package api

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// hardwareInfo — ядра CPU, частота, модель, RAM всего/свободно, диск. Для дашборда.
type hardwareInfo struct {
	CPUCores  int     `json:"cpu_cores"`
	CPUModel  string  `json:"cpu_model"`
	CPUMhz    float64 `json:"cpu_mhz"`
	RAMTotalMB int    `json:"ram_total_mb"`
	RAMUsedMB  int    `json:"ram_used_mb"`
	RAMFreeMB  int    `json:"ram_free_mb"`
	DiskTotalGB float64 `json:"disk_total_gb"`
	DiskUsedGB  float64 `json:"disk_used_gb"`
	DiskFreeGB  float64 `json:"disk_free_gb"`
	UptimeSec  int64   `json:"uptime_sec"`
	LoadAvg1   float64 `json:"loadavg1"`
	LoadAvg5   float64 `json:"loadavg5"`
	LoadAvg15  float64 `json:"loadavg15"`
	GoRoutines int     `json:"go_routines"`
}

func readHardware() hardwareInfo {
	h := hardwareInfo{CPUCores: runtime.NumCPU(), GoRoutines: runtime.NumGoroutine()}
	// /proc/cpuinfo — модель + частота
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") && h.CPUModel == "" {
				h.CPUModel = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			}
			if strings.HasPrefix(line, "cpu MHz") && h.CPUMhz == 0 {
				f, _ := strconv.ParseFloat(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), 64)
				h.CPUMhz = f
			}
		}
	}
	// /proc/meminfo — RAM всего/свободно (система, не только панель)
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, free, avail, buffers, cached int64
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 { continue }
			v, _ := strconv.ParseInt(f[1], 10, 64) // kB
			switch f[0] {
			case "MemTotal:": total = v
			case "MemFree:": free = v
			case "MemAvailable:": avail = v
			case "Buffers:": buffers = v
			case "Cached:": cached = v
			}
		}
		h.RAMTotalMB = int(total / 1024)
		if avail > 0 {
			h.RAMFreeMB = int(avail / 1024)
		} else {
			h.RAMFreeMB = int((free + buffers + cached) / 1024)
		}
		h.RAMUsedMB = h.RAMTotalMB - h.RAMFreeMB
	}
	// /proc/uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(data))
		if len(f) > 0 { up, _ := strconv.ParseFloat(f[0], 64); h.UptimeSec = int64(up) }
	}
	// /proc/loadavg
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(data))
		if len(f) >= 3 {
			h.LoadAvg1, _ = strconv.ParseFloat(f[0], 64)
			h.LoadAvg5, _ = strconv.ParseFloat(f[1], 64)
			h.LoadAvg15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	// диск через statfs
	var st statfsT
	if statfs("/", &st) == nil {
		total := uint64(st.Blocks) * uint64(st.Bsize)
		free := uint64(st.Bavail) * uint64(st.Bsize)
		h.DiskTotalGB = float64(total) / 1e9
		h.DiskFreeGB = float64(free) / 1e9
		h.DiskUsedGB = h.DiskTotalGB - h.DiskFreeGB
	}
	return h
}