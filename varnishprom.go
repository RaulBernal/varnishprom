package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	log "log/slog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metric struct {
	Description string                `json:"description"`
	Type        string                `json:"flag"`
	Format      string                `json:"format"`
	Value       uint64                `json:"value"`
	LastUpdated uint64                `json:"-"`
	Name        string                `json:"-"`
	LabelNames  []string              `json:"-"`
	LabelValues []string              `json:"-"`
	Source      string                `json:"-"`
	Gauge       prometheus.GaugeVec   `json:"-"`
	Counter     prometheus.CounterVec `json:"-"`
}

type VarnishStats74 struct {
	Version   int               `json:"version"`
	Timestamp string            `json:"timestamp"`
	Metrics   map[string]Metric `json:"counters"`
}

type GaugeOverView struct {
	Name       string
	Gauge      prometheus.GaugeVec
	Labels     []string
	Source     string
	LastUpdate uint64
}

type CounterOverView struct {
	Name       string
	Counter    prometheus.CounterVec
	Labels     []string
	Source     string
	LastUpdate uint64
}

type VarnishStats60 struct {
	Metrics map[string]Metric
}

type VarnishStats interface {
	GetMetrics() map[string]Metric
}

type PromCounter struct {
	counterVec *prometheus.CounterVec
	LastUpdate uint64
}

func (v VarnishStats60) GetMetrics() map[string]Metric {
	return v.Metrics
}

func (v VarnishStats74) GetMetrics() map[string]Metric {
	return v.Metrics
}

var (
	dynamicGauges             = make(map[string]*prometheus.GaugeVec)
	dynamicGaugesMetricsMutex = &sync.Mutex{}
	dynamicCounters           = make(map[string]*PromCounter)
	dynamicCountsMetricsMutex = &sync.Mutex{}
	CounterOverViewMutex      = &sync.Mutex{}
	gaugeOverView             = make(map[string]*Metric)
	activeVcl                 = "boot"
	parsedVcl                 = "boot"
	varnishVersion            = "varnish-6.0.12"
	commitHash                = ""
	version                   = "dev"     // goreleaser will fill this in
	commit                    = "none"    // goreleaser will fill this in
	date                      = "unknown" // goreleaser will fill this in
	tickerCount               = 0
)

// getGauge crea o devuelve un Gauge existente
func getGauge(key string, desc string, labelNames []string) *prometheus.GaugeVec {
	dynamicGaugesMetricsMutex.Lock()
	defer dynamicGaugesMetricsMutex.Unlock()

	if gauge, ok := dynamicGauges[key]; ok {
		return gauge
	}
	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: key,
			Help: desc,
		},
		labelNames,
	)
	prometheus.MustRegister(gauge)
	dynamicGauges[key] = gauge

	return gauge
}

// getCounter crea o devuelve un Counter existente
func getCounter(key string, desc string, labelNames []string) *PromCounter {
	dynamicCountsMetricsMutex.Lock()
	defer dynamicCountsMetricsMutex.Unlock()

	if counter, ok := dynamicCounters[key]; ok {
		return counter
	}
	counter := new(PromCounter)
	counter.counterVec = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: key,
			Help: desc,
		},
		labelNames,
	)
	prometheus.MustRegister(counter.counterVec)
	dynamicCounters[key] = counter

	return counter
}

func setGauge(metric Metric) {
	gauge := getGauge(metric.Name, metric.Description, metric.LabelNames)
	gauge.WithLabelValues(metric.LabelValues...).Set(float64(metric.Value))
	metric.LastUpdated = uint64(tickerCount)
	metric.Gauge = *gauge
	identifier := metric.Name + strings.Join(metric.LabelValues, "")
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	sanitized := reg.ReplaceAllString(identifier, "")
	gaugeOverView[sanitized] = &metric
}

func main() {
	fqdn, _ := os.Hostname()
	shortName := strings.Split(fqdn, ".")[0]
	var listen = flag.String("i", "127.0.0.1:7083", "Listen interface for metrics endpoint")
	var path = flag.String("p", "/metrics", "Path for metrics endpoint")
	var logKey = flag.String("k", "prom", "logkey to look for promethus metrics")
	var logEnabled = flag.Bool("l", false, "Start varnishlog parser")
	var statEnabled = flag.Bool("s", false, "Start varnishstat parser")
	var adminHost = flag.String("T", "", "Varnish admin interface")
	var gitCheck = flag.String("g", "", "Check git commit hash of given directory")
	var secretsFile = flag.String("S", "", "Varnish admin secret file")
	var versionFlag = flag.Bool("v", false, "Print version and exit")
	var hostname = flag.String("h", shortName, "Hostname to use in metrics, defaults to hostname -S")
	// var collapse = flag.String("c", "^kozebamze$", "Regexp against director to collapse backend")
	var logLevel = flag.String("V", "info", "Loglevel for varnishprom (debug,info,warn,error)")
	flag.Parse()

	switch *logLevel {
	case "error":
		log.SetLogLoggerLevel(log.LevelError)
	case "warn":
		log.SetLogLoggerLevel(log.LevelWarn)
	case "debug":
		log.SetLogLoggerLevel(log.LevelDebug)
	}
	log.Debug("We are debugging")

	if *versionFlag {
		fmt.Printf("varnishprom version: %s, commit: %s, date: %s\n", version, commit, date)
		os.Exit(0)
	}

	if *logEnabled {
		go func() {
			for {
				log.Info("Starting varnishlog parser", "logkey", *logKey)
				var varnishlog = exec.Command("varnishlog", "-i", "VCL_Log")
				var varnishlogOutput, err = varnishlog.StdoutPipe()
				if err != nil {
					panic(err)
				}
				varnishlog.Start()
				scanner := bufio.NewScanner(varnishlogOutput)
				for scanner.Scan() {
					line := scanner.Text()
					keyIndex := strings.Index(line, " "+*logKey+"=")
					if keyIndex != -1 {
						extracted := line[keyIndex+len(*logKey)+2:]
						parts := strings.SplitN(extracted, " ", 2)
						if len(parts) < 2 {
							continue
						}
						counterName := "varnishlog_" + strings.TrimSpace(parts[0])
						labels := strings.TrimSpace(parts[1])
						desc := "Varnishlog Counter"
						labelPairs := strings.Split(labels, ",")
						labelNames := make([]string, 0, len(labelPairs))
						labelValues := make([]string, 0, len(labelPairs))
						for _, pair := range labelPairs {
							pairParts := strings.SplitN(pair, "=", 2)
							if len(pairParts) < 2 {
								continue
							}
							labelName := pairParts[0]
							labelValue := pairParts[1]
							if labelName == "desc" {
								desc = labelValue
							}
							labelNames = append(labelNames, labelName)
							labelValues = append(labelValues, labelValue)
						}
						labelValues = append(labelValues, *hostname)
						labelNames = append(labelNames, "host")
						counter := getCounter(counterName, desc, labelNames)
						counter.counterVec.WithLabelValues(labelValues...).Inc()
						log.Debug("varnishlog", "id", counterName)
					}
				}
				log.Error("Lost connection to varnishlog")
				time.Sleep(time.Second * 5)
			}
		}()
	}

	if *statEnabled {
		log.Info("Starting varnishstat parser")
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		defer log.Info("Program is exiting")
		var mutex sync.Mutex

		go func() {
			for range ticker.C {
				log.Debug("New varnishstat Tick")
				if !mutex.TryLock() {
					log.Warn("Mutex is locked, skipping tick, we might have a problem")
					continue
				}
				tickerCount++
				var varnishadm *exec.Cmd
				if len(*adminHost) > 0 {
					varnishadm = exec.Command("varnishadm", "-T", *adminHost, "-S", *secretsFile, "banner")
				} else {
					varnishadm = exec.Command("varnishadm", "banner")
				}
				var varnishadmOutput, err = varnishadm.Output()
				if err != nil {
					log.Warn("Error running varnishadm", "err", err)
					log.Warn(varnishadm.String())
					mutex.Unlock()
					continue
				}
				lines := strings.Split(string(varnishadmOutput), "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "varnish") {
						columns := strings.Fields(line)
						varnishVersion = columns[0]
					}
				}
				log.Debug("varnish", "version", varnishVersion)

				if *adminHost != "" {
					varnishadm = exec.Command("varnishadm", "-T", *adminHost, "-S", *secretsFile, "vcl.list")
				} else {
					varnishadm = exec.Command("varnishadm", "vcl.list")
				}
				varnishadmOutput, err = varnishadm.Output()
				if err != nil {
					log.Warn("Error running varnishadm: ", "error", err.Error())
					log.Warn(fmt.Sprintf("varnishadm -T %s -S %s vcl.list ", *adminHost, *secretsFile))
					break
				}
				lines = strings.Split(string(varnishadmOutput), "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "active") {
						columns := strings.Fields(line)
						if len(columns) >= 5 {
							parsedVcl = columns[4]
							break
						} else if len(columns) >= 4 {
							parsedVcl = columns[3]
							break
						}
					}
				}
				log.Debug("VCL decifered", "parsedVcl", parsedVcl, "activeVcl", activeVcl)
				if parsedVcl != activeVcl {
					log.Info(fmt.Sprintf("Active VCL changed from %s to %s", activeVcl, parsedVcl))
					activeVcl = parsedVcl
				}

				if *gitCheck != "" {
					gitCmd := exec.Command("git", "-C", *gitCheck, "log", "-n", "1", "--pretty=format:%H")
					gitCmdOutput, err := gitCmd.Output()
					if err != nil {
						log.Warn("Error running git: ", "error", err)
						break
					}
					commitHash = string(gitCmdOutput)
					setGauge(Metric{
						Name:        "varnishstat_version",
						Description: "Version Varnish running",
						LabelNames:  []string{"version", "githash", "activevcl", "varnishprom", "host"},
						LabelValues: []string{varnishVersion, commitHash, activeVcl, version, *hostname},
					})
				} else {
					log.Debug("We do not have a githash")
					setGauge(Metric{
						Name:        "varnishstat_version",
						Description: "Version Varnish running",
						LabelNames:  []string{"version", "activevcl", "varnishprom", "host"},
						LabelValues: []string{varnishVersion, activeVcl, version, *hostname},
					})
				}

				varnishstat := exec.Command("varnishstat", "-1", "-j")
				varnishstatOutput, err := varnishstat.StdoutPipe()
				if err != nil {
					log.Warn("Failed varnishstat:", "error", err)
					break
				}
				if err := varnishstat.Start(); err != nil {
					log.Warn("Failed starting varnishstat:", "error", err)
					break
				}

				var stats VarnishStats
				if strings.Contains(varnishVersion, "6.0") {
					var filteredOutput bytes.Buffer
					scanner := bufio.NewScanner(varnishstatOutput)
					for scanner.Scan() {
						line := scanner.Text()
						if !strings.Contains(line, "timestamp") {
							filteredOutput.WriteString(line)
							filteredOutput.WriteString("\n")
						}
					}
					decoder := json.NewDecoder(bufio.NewReader(&filteredOutput))
					var stats6 VarnishStats60
					err = decoder.Decode(&stats6.Metrics)
					stats = stats6
				} else {
					var stats7 VarnishStats74
					decoder := json.NewDecoder(varnishstatOutput)
					err = decoder.Decode(&stats7)
					stats = stats7
				}
				if err != nil {
					log.Warn("Can't decode json from varnishstat", "error", err)
					return
				}

				// Procesamiento de métricas: se omiten las que empiezan por "KVSTORE" y "VBE."
				metrics := stats.GetMetrics()
				for key, metric := range metrics {
					if metric.Type == "c" && metric.Value == 0 && !strings.HasSuffix(key, ".req") {
						continue
					}
					if strings.HasPrefix(key, "KVSTORE") || strings.HasPrefix(key, "VBE.") {
						continue
					}

					// Se deja el formato original para asignar el nombre y procesar según el tipo
					metric.Name = "varnishstat_" + strings.ReplaceAll(key, ".", "_")
					if metric.Type == "g" {
						metric.LabelNames = []string{"host"}
						metric.LabelValues = []string{*hostname}
						setGauge(metric)
					} else if metric.Type == "c" {
						metric.LabelNames = []string{"host"}
						metric.LabelValues = []string{*hostname}
						setGauge(metric)
					} else {
						log.Debug("Unknown metric type", "metrictype", metric.Type)
					}
				}

				for metricname, metric := range gaugeOverView {
					if int(metric.LastUpdated) < tickerCount {
						metric.Gauge.DeleteLabelValues(metric.LabelValues...)
						delete(gaugeOverView, metricname)
						log.Debug("Deleting old metrics ", "Metric", metricname)
					}
				}
				if err := varnishstat.Wait(); err != nil {
					log.Warn("Error waiting for varnishstat", "error", err)
				}
				mutex.Unlock()
			}
		}()
	}

	if *statEnabled || *logEnabled {
		log.Info("Starting Prometheus metrics endpoint on " + *listen + *path)
		http.Handle(*path, promhttp.Handler())
		err := http.ListenAndServe(*listen, nil)
		if err != nil {
			log.Error("Failed to start server:", "error", err)
		}
	} else {
		log.Error("Not starting log or statsparser. Enable -l (log) -s (stats) or both on the commandline")
		os.Exit(1)
	}
}
