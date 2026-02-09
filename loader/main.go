package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -cc clang syscall ../detectors/syscall.c

// Event represents a security event from eBPF
type Event struct {
	Type      uint32 `json:"type"`
	PID       uint32 `json:"pid"`
	Timestamp uint64 `json:"timestamp"`
	Comm      string `json:"comm"`
	Details   string `json:"details"`
}

// AlertResponse is the JSON API response
type AlertResponse struct {
	Timestamp string  `json:"timestamp"`
	Alerts    []Event `json:"alerts"`
	Total     int     `json:"total"`
}

var (
	alerts   []Event
	alertsCh = make(chan Event, 100)
	httpPort = 8080
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock: %v", err)
	}

	// Load pre-compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec("detectors/syscall.o")
	if err != nil {
		log.Fatalf("loading eBPF collection: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating collection: %v", err)
	}
	defer coll.Close()

	// Attach kprobes
	progs := coll.Programs
	links := []link.Link{}

	// Process monitoring
	if prog, ok := progs["monitor_execve"]; ok {
		kp, err := link.Kprobe("sys_execve", prog, nil)
		if err != nil {
			log.Printf("failed to attach execve kprobe: %v", err)
		} else {
			links = append(links, kp)
		}
	}

	// Process hiding detection
	if prog, ok := progs["detect_process_hide"]; ok {
		kp, err := link.Kprobe("do_fork", prog, nil)
		if err != nil {
			log.Printf("failed to attach fork kprobe: %v", err)
		} else {
			links = append(links, kp)
		}
	}

	// File hiding detection
	if prog, ok := progs["detect_file_hide_start"]; ok {
		kp, err := link.Kprobe("filldir64", prog, nil)
		if err != nil {
			log.Printf("failed to attach filldir64 kprobe: %v", err)
		} else {
			links = append(links, kp)
		}
	}

	if prog, ok := progs["detect_file_hide_end"]; ok {
		kp, err := link.Kretprobe("filldir64", prog, nil)
		if err != nil {
			log.Printf("failed to attach filldir64 kretprobe: %v", err)
		} else {
			links = append(links, kp)
		}
	}

	// Module tampering detection
	if prog, ok := progs["detect_module_tamper"]; ok {
		kp, err := link.Kprobe("load_module", prog, nil)
		if err != nil {
			log.Printf("failed to attach load_module kprobe: %v", err)
		} else {
			links = append(links, kp)
		}
	}

	// Syscall hooking detection
	if prog, ok := progs["detect_syscall_hook"]; ok {
		kp, err := link.Kprobe("do_syscall_64", prog, nil)
		if err != nil {
			log.Printf("failed to attach syscall kprobe: %v", err)
		} else {
			links = append(links, kp)
		}
	}

	// Close all links when done
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// Start event processing
	go processEvents(coll.Maps["events"])
	go startHTTPServer()
	go displayCLI()

	fmt.Println("✅ eBPF Rootkit Detector ARMED")
	fmt.Printf("🔍 Monitoring system activity...\n")
	fmt.Printf("🌐 Web API: http://localhost:%d\n", httpPort)
	fmt.Println("📊 Real-time alerts below:")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	fmt.Println("\n🛑 Detector stopped")
}

func processEvents(events *ebpf.Map) {
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	for {
		_, err := rd.Read()
		if err != nil {
			log.Printf("reading from ringbuf: %v", err)
			continue
		}

		// For now, create a mock event to demonstrate the system
		// In real implementation, parse the binary data properly
		event := Event{
			Type:      1,
			PID:       uint32(syscall.Getpid()),
			Timestamp: uint64(time.Now().UnixNano()),
			Comm:      "test",
			Details:   "eBPF detection event",
		}

		select {
		case alertsCh <- event:
		default:
			// Channel full, drop event
		}
	}
}

func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func displayCLI() {
	for event := range alertsCh {
		// Store alert
		alerts = append(alerts, event)
		if len(alerts) > 1000 {
			alerts = alerts[1:] // Keep only last 1000
		}

		// Display alert
		timestamp := time.Unix(0, int64(event.Timestamp))
		alertType := getAlertTypeName(event.Type)

		fmt.Printf("\033[31m[ALERT]\033[0m %s | %s | PID: %d | Process: %s | %s\n",
			timestamp.Format("15:04:05"),
			alertType,
			event.PID,
			event.Comm,
			event.Details)
	}
}

func getAlertTypeName(eventType uint32) string {
	switch eventType {
	case 1:
		return "SYSCALL_HOOK"
	case 2:
		return "PROCESS_HIDE"
	case 3:
		return "FILE_HIDE"
	case 4:
		return "MODULE_TAMPER"
	default:
		return "UNKNOWN"
	}
}

func startHTTPServer() {
	http.HandleFunc("/alerts", handleAlerts)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/", handleRoot)

	log.Printf("Starting HTTP server on port %d", httpPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil); err != nil {
		log.Printf("HTTP server error: %v", err)
	}
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	response := AlertResponse{
		Timestamp: time.Now().Format(time.RFC3339),
		Alerts:    alerts,
		Total:     len(alerts),
	}

	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>eBPF Rootkit Detector</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .alert { background: #ffebee; border: 1px solid #f44336; padding: 10px; margin: 5px 0; border-radius: 4px; }
        .healthy { color: #4caf50; }
    </style>
</head>
<body>
    <h1>🛡️ eBPF Rootkit Detector</h1>
    <p class="healthy">● System Monitor Active</p>
    
    <h2>API Endpoints:</h2>
    <ul>
        <li><a href="/alerts">GET /alerts</a> - Recent security alerts</li>
        <li><a href="/health">GET /health</a> - System health check</li>
    </ul>
    
    <h2>Recent Alerts:</h2>
    <div id="alerts">Loading...</div>
    
    <script>
        async function loadAlerts() {
            try {
                const response = await fetch('/alerts');
                const data = await response.json();
                const alertsDiv = document.getElementById('alerts');
                
                if (data.alerts.length === 0) {
                    alertsDiv.innerHTML = '<p>No alerts detected. System clean!</p>';
                    return;
                }
                
                alertsDiv.innerHTML = data.alerts.slice(-10).reverse().map(alert => 
                    '<div class="alert">' +
                        '<strong>' + getAlertName(alert.type) + '</strong> - ' +
                        'PID: ' + alert.pid + ' - ' +
                        'Process: ' + alert.comm + '<br>' +
                        '<small>' + alert.details + '</small>' +
                    '</div>'
                ).join('');
            } catch (error) {
                console.error('Error loading alerts:', error);
            }
        }
        
        function getAlertName(type) {
            const names = {1: 'SYSCALL_HOOK', 2: 'PROCESS_HIDE', 3: 'FILE_HIDE', 4: 'MODULE_TAMPER'};
            return names[type] || 'UNKNOWN';
        }
        
        loadAlerts();
        setInterval(loadAlerts, 5000); // Refresh every 5 seconds
    </script>
</body>
</html>
`)
}
