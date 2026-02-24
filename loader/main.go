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

	// Try loading with default options (without BTF)
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
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>eBPF Rootkit Detector</title>
    <link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Symbols+Rounded" rel="stylesheet">
    <style>
        :root {
            --md-sys-color-primary: #006A6A;
            --md-sys-color-on-primary: #FFFFFF;
            --md-sys-color-primary-container: #6FF7F6;
            --md-sys-color-on-primary-container: #002020;
            --md-sys-color-secondary: #4A6363;
            --md-sys-color-on-secondary: #FFFFFF;
            --md-sys-color-surface: #FAFDFC;
            --md-sys-color-surface-variant: #DBE4E4;
            --md-sys-color-on-surface: #191C1C;
            --md-sys-color-outline: #6F7979;
            --md-sys-color-error: #BA1A1A;
            --md-sys-color-on-error: #FFFFFF;
            --md-sys-color-error-container: #FFDAD6;
            --md-sys-color-on-error-container: #410002;
            --md-sys-typescale-body-large: 16px;
            --md-sys-typescale-body-medium: 14px;
            --md-sys-typescale-headline-medium: 28px;
            --md-sys-typescale-title-large: 22px;
            --md-sys-typescale-title-medium: 16px;
            --md-sys-typescale-label-large: 14px;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Google Sans', 'Roboto', sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4efe9 100%);
            min-height: 100vh;
            color: var(--md-sys-color-on-surface);
            line-height: 1.5;
        }
        
        .app-bar {
            background: linear-gradient(135deg, #006A6A 0%, #00897B 100%);
            color: white;
            padding: 24px 32px;
            box-shadow: 0 4px 20px rgba(0, 106, 106, 0.3);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .app-bar h1 {
            font-size: 24px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .app-bar .material-symbols-rounded {
            font-size: 32px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .stat-card {
            background: white;
            border-radius: 16px;
            padding: 20px 24px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
            transition: transform 0.2s, box-shadow 0.2s;
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
        }
        
        .stat-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        
        .stat-icon.syscalls { background: #E3F2FD; color: #1565C0; }
        .stat-icon.processes { background: #FFF3E0; color: #E65100; }
        .stat-icon.files { background: #F3E5F5; color: #7B1FA2; }
        .stat-icon.modules { background: #FBE9E7; color: #BF360C; }
        
        .stat-info h3 {
            font-size: 14px;
            font-weight: 400;
            color: var(--md-sys-color-outline);
            margin-bottom: 4px;
        }
        
        .stat-info .value {
            font-size: 28px;
            font-weight: 500;
            color: var(--md-sys-color-on-surface);
        }
        
        .section {
            background: white;
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }
        
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--md-sys-color-surface-variant);
        }
        
        .section-header h2 {
            font-size: 18px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
        }
        
        .status-badge.active {
            background: #E8F5E9;
            color: #2E7D32;
        }
        
        .status-badge .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #4CAF50;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .alerts-container {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        
        .alert-card {
            display: flex;
            align-items: flex-start;
            gap: 16px;
            padding: 16px;
            border-radius: 12px;
            background: var(--md-sys-color-surface);
            border-left: 4px solid;
            transition: transform 0.2s;
        }
        
        .alert-card:hover {
            transform: translateX(4px);
        }
        
        .alert-card.type-1 { border-left-color: #1565C0; background: #E3F2FD; }
        .alert-card.type-2 { border-left-color: #E65100; background: #FFF3E0; }
        .alert-card.type-3 { border-left-color: #7B1FA2; background: #F3E5F5; }
        .alert-card.type-4 { border-left-color: #BF360C; background: #FBE9E7; }
        
        .alert-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }
        
        .alert-card.type-1 .alert-icon { background: #1565C0; color: white; }
        .alert-card.type-2 .alert-icon { background: #E65100; color: white; }
        .alert-card.type-3 .alert-icon { background: #7B1FA2; color: white; }
        .alert-card.type-4 .alert-icon { background: #BF360C; color: white; }
        
        .alert-content {
            flex: 1;
        }
        
        .alert-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 4px;
        }
        
        .alert-type {
            font-weight: 600;
            font-size: 14px;
        }
        
        .alert-time {
            font-size: 12px;
            color: var(--md-sys-color-outline);
        }
        
        .alert-details {
            font-size: 13px;
            color: var(--md-sys-color-secondary);
            margin-bottom: 8px;
        }
        
        .alert-meta {
            display: flex;
            gap: 16px;
            font-size: 12px;
            color: var(--md-sys-color-outline);
            font-family: 'JetBrains Mono', monospace;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--md-sys-color-outline);
        }
        
        .empty-state .material-symbols-rounded {
            font-size: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        .empty-state h3 {
            font-size: 18px;
            margin-bottom: 8px;
            color: var(--md-sys-color-on-surface);
        }
        
        .api-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }
        
        .api-card {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px;
            border-radius: 12px;
            background: var(--md-sys-color-surface);
            text-decoration: none;
            color: var(--md-sys-color-on-surface);
            transition: background 0.2s;
        }
        
        .api-card:hover {
            background: var(--md-sys-color-surface-variant);
        }
        
        .api-card .method {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            font-weight: 500;
            padding: 4px 8px;
            border-radius: 4px;
            background: var(--md-sys-color-primary-container);
            color: var(--md-sys-color-on-primary-container);
        }
        
        .api-card .endpoint {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }
        
        .refresh-indicator {
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: white;
            padding: 12px 20px;
            border-radius: 30px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { transform: translateY(100px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .refresh-indicator .material-symbols-rounded {
            font-size: 20px;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .app-bar { padding: 16px 20px; }
            .stats-grid { grid-template-columns: 1fr; }
            .section { padding: 16px; }
        }
    </style>
</head>
<body>
    <div class="app-bar">
        <h1>
            <span class="material-symbols-rounded">shield</span>
            eBPF Rootkit Detector
        </h1>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon syscalls">
                    <span class="material-symbols-rounded">code</span>
                </div>
                <div class="stat-info">
                    <h3>Syscall Events</h3>
                    <div class="value" id="syscall-count">0</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon processes">
                    <span class="material-symbols-rounded">memory</span>
                </div>
                <div class="stat-info">
                    <h3>Process Events</h3>
                    <div class="value" id="process-count">0</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon files">
                    <span class="material-symbols-rounded">folder</span>
                </div>
                <div class="stat-info">
                    <h3>File Events</h3>
                    <div class="value" id="file-count">0</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon modules">
                    <span class="material-symbols-rounded">extension</span>
                </div>
                <div class="stat-info">
                    <h3>Module Events</h3>
                    <div class="value" id="module-count">0</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2>
                    <span class="material-symbols-rounded">notifications</span>
                    Security Alerts
                </h2>
                <div class="status-badge active">
                    <span class="dot"></span>
                    Monitoring Active
                </div>
            </div>
            <div class="alerts-container" id="alerts-container">
                <div class="empty-state">
                    <span class="material-symbols-rounded">verified_user</span>
                    <h3>System Clean</h3>
                    <p>No suspicious activity detected</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2>
                    <span class="material-symbols-rounded">api</span>
                    API Endpoints
                </h2>
            </div>
            <div class="api-section">
                <a href="/alerts" class="api-card">
                    <span class="method">GET</span>
                    <span class="endpoint">/alerts</span>
                </a>
                <a href="/health" class="api-card">
                    <span class="method">GET</span>
                    <span class="endpoint">/health</span>
                </a>
            </div>
        </div>
    </div>
    
    <div class="refresh-indicator">
        <span class="material-symbols-rounded">sync</span>
        Live
    </div>
    
    <script>
        const alertTypeNames = {
            1: { name: 'SYSCALL HOOK', icon: 'code' },
            2: { name: 'PROCESS HIDE', icon: 'visibility_off' },
            3: { name: 'FILE HIDE', icon: 'folder_off' },
            4: { name: 'MODULE TAMPER', icon: 'extension_off' }
        };
        
        function formatTime(timestamp) {
            const date = new Date(timestamp / 1000000);
            return date.toLocaleTimeString();
        }
        
        function formatTimeAgo(timestamp) {
            const now = Date.now();
            const time = timestamp / 1000000;
            const diff = now - time;
            
            if (diff < 60000) return 'Just now';
            if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
            return Math.floor(diff / 3600000) + 'h ago';
        }
        
        async function loadAlerts() {
            try {
                const response = await fetch('/alerts');
                const data = await response.json();
                
                const counts = { 1: 0, 2: 0, 3: 0, 4: 0 };
                const container = document.getElementById('alerts-container');
                
                if (data.alerts.length === 0) {
                    container.innerHTML = '<div class="empty-state"><span class="material-symbols-rounded">verified_user</span><h3>System Clean</h3><p>No suspicious activity detected</p></div>';
                } else {
                    const recentAlerts = data.alerts.slice(-10).reverse();
                    
                    container.innerHTML = recentAlerts.map(function(alert) {
                        counts[alert.type] = (counts[alert.type] || 0) + 1;
                        const typeInfo = alertTypeNames[alert.type] || { name: 'UNKNOWN', icon: 'help' };
                        
                        return '<div class="alert-card type-' + alert.type + '">' +
                            '<div class="alert-icon"><span class="material-symbols-rounded">' + typeInfo.icon + '</span></div>' +
                            '<div class="alert-content">' +
                            '<div class="alert-header"><span class="alert-type">' + typeInfo.name + '</span><span class="alert-time">' + formatTimeAgo(alert.timestamp) + '</span></div>' +
                            '<div class="alert-details">' + alert.details + '</div>' +
                            '<div class="alert-meta"><span>PID: ' + alert.pid + '</span><span>Process: ' + alert.comm + '</span></div>' +
                            '</div></div>';
                    }).join('');
                }
                
                document.getElementById('syscall-count').textContent = counts[1];
                document.getElementById('process-count').textContent = counts[2];
                document.getElementById('file-count').textContent = counts[3];
                document.getElementById('module-count').textContent = counts[4];
                
            } catch (error) {
                console.error('Error loading alerts:', error);
            }
        }
        
        loadAlerts();
        setInterval(loadAlerts, 3000);
    </script>
</body>
</html>`)
}
