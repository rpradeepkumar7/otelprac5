package main

import (
    "context"
    "encoding/json"
    "log"
    "net"
    "net/http"
    "os"
    "runtime"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "golang.org/x/sys/unix"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
    "go.opentelemetry.io/otel/sdk/resource"
    "go.opentelemetry.io/otel/sdk/trace"
    "go.opentelemetry.io/otel/attribute"
)

// LogEntry structure for OpenTelemetry log
type LogEntry struct {
    Timestamp           string              `json:"Timestamp"`
    ObservedTimestamp   string              `json:"ObservedTimestamp"`
    TraceID             string              `json:"TraceId"`
    SpanID              string              `json:"SpanId"`
    SeverityText        string              `json:"SeverityText"`
    SeverityNumber      string              `json:"SeverityNumber"`
    Body                string              `json:"Body"`
    Resource            map[string]string   `json:"Resource"`
    InstrumentationScope map[string]string  `json:"InstrumentationScope"`
    Attributes          map[string]string   `json:"Attributes"`
    EventData           map[string]string   `json:"EventData"`
    Exception           map[string]string   `json:"Exception"`
    Duration            string              `json:"Duration"`
    Status              string              `json:"Status"`
    LogLevel            string              `json:"LogLevel"`
    Hostname            string              `json:"host.name"`
    IPAddress           string              `json:"host.ip"`
    MacAddress          string              `json:"host.mac"`
    OSType              string              `json:"os.type"`
    OSVersion           string              `json:"os.version"`
    FirewallStatus      string              `json:"firewall.status"`
    NetworkLatency      string              `json:"network.latency"`
    CPUUsage            string              `json:"cpu.usage"`
    MemoryUsage         string              `json:"memory.usage"`
    DiskUsage           string              `json:"disk.usage"`
    Event               string              `json:"event"`
}

// Get system info (hostname, IP, MAC, OS type, and OS version)
func getSystemInfo() (string, string, string, string, string) {
    hostname, _ := os.Hostname()

    // Get IP and MAC address
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Fatal(err)
    }

    var ipAddress, macAddress string
    for _, iface := range interfaces {
        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }

        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)
            if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
                ipAddress = ipNet.IP.String()
                macAddress = iface.HardwareAddr.String()
                break
            }
        }
        if ipAddress != "" && macAddress != "" {
            break
        }
    }

    // Get OS type and version
    osType := runtime.GOOS
    osVersion := getOSVersion()

    return hostname, ipAddress, macAddress, osType, osVersion
}

// Get OS version using unix syscall
func getOSVersion() string {
    var utsname unix.Utsname
    if err := unix.Uname(&utsname); err != nil {
        return "unknown"
    }
    return string(utsname.Release[:])
}

// Get firewall status (dummy example, replace with actual logic)
func getFirewallStatus() string {
    // Implement actual firewall check logic if available
    return "enabled"
}

// Simulate network latency (dummy example)
func getNetworkLatency() string {
    // Replace with actual network latency measurement logic
    return "50ms"
}

// Simulate CPU and Memory usage (dummy examples)
func getCPUUsage() string {
    // Implement logic to get CPU usage
    return "30%"
}

func getMemoryUsage() string {
    // Implement logic to get Memory usage
    return "60%"
}

// Simulate Disk usage (dummy example)
func getDiskUsage() string {
    // Implement logic to get Disk usage
    return "70%"
}

func main() {
    // Set up OpenTelemetry trace exporter
    traceExporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
    if err != nil {
        log.Fatal(err)
    }

    // Get system information
    hostname, ipAddress, macAddress, osType, osVersion := getSystemInfo()
    firewallStatus := getFirewallStatus()
    networkLatency := getNetworkLatency()
    cpuUsage := getCPUUsage()
    memoryUsage := getMemoryUsage()
    diskUsage := getDiskUsage()

    // Set up Resource with Attributes
    res, err := resource.New(
        context.Background(),
        resource.WithAttributes(
            attribute.String("service.name", "web-backend"),
            attribute.String("host.name", hostname),
            attribute.String("host.ip", ipAddress),
            attribute.String("host.mac", macAddress),
            attribute.String("os.type", osType),
            attribute.String("os.version", osVersion),
            attribute.String("firewall.status", firewallStatus),
            attribute.String("network.latency", networkLatency),
            attribute.String("cpu.usage", cpuUsage),
            attribute.String("memory.usage", memoryUsage),
            attribute.String("disk.usage", diskUsage),
        ),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Set up Trace Provider
    tracerProvider := trace.NewTracerProvider(
        trace.WithBatcher(traceExporter),
        trace.WithResource(res),
    )
    defer func() {
        if err := tracerProvider.Shutdown(context.Background()); err != nil {
            log.Fatal(err)
        }
    }()

    // Set up Prometheus Metrics Exporter
    reg := prometheus.NewRegistry()
    // Register custom metrics here if needed

    // Start HTTP server for Prometheus metrics
    http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
    go func() {
        log.Println("Starting Prometheus metrics server on port 9090")
        if err := http.ListenAndServe(":9090", nil); err != nil {
            log.Fatal(err)
        }
    }()

    // Set the global trace provider
    otel.SetTracerProvider(tracerProvider)

    // Use the tracer (example usage)
    tracer := otel.Tracer("example-tracer")
    _, span := tracer.Start(context.Background(), "example-span")
    defer span.End()

    // Example Log Entry with additional attributes
    logEntry := LogEntry{
        Timestamp:         time.Now().Format(time.RFC3339),
        ObservedTimestamp: time.Now().Add(100 * time.Millisecond).Format(time.RFC3339),
        TraceID:           "abcd1234",
        SpanID:            "efgh5678",
        SeverityText:      "ERROR",
        SeverityNumber:    "17",
        Body:              "An error occurred while processing the request.",
        Resource: map[string]string{
            "service.name": "web-backend",
            "host.name":    hostname,
            "host.ip":      ipAddress,
            "host.mac":     macAddress,
            "os.type":      osType,
            "os.version":   osVersion,
        },
        InstrumentationScope: map[string]string{
            "Name":    "GoLogger",
            "Version": "1.0.0",
        },
        Attributes: map[string]string{
            "http.method":      "GET",
            "http.status_code": "500",
            "http.url":         "http://example.com",
            "db.operation":     "SELECT",
        },
        EventData: map[string]string{
            "event.name": "request_error",
            "event.type": "error",
        },
        Exception: map[string]string{
            "exception.message":  "Database connection failed",
            "exception.type":     "DatabaseError",
            "exception.stacktrace": "at com.example.Database.connect(Database.java:42)\n...more stack trace...",
        },
        Duration:      "100ms",
        Status:        "failed",
        LogLevel:      "error",
        Hostname:      hostname,
        IPAddress:     ipAddress,
        MacAddress:    macAddress,
        OSType:        osType,
        OSVersion:     osVersion,
        FirewallStatus: firewallStatus,
        NetworkLatency: networkLatency,
        CPUUsage:      cpuUsage,
        MemoryUsage:   memoryUsage,
        DiskUsage:     diskUsage,
        Event:         "SystemCriticalEvent",
    }

    // Convert log entry to JSON and print it
    logEntryJSON, err := json.MarshalIndent(logEntry, "", "  ")
    if err != nil {
        log.Fatal(err)
    }
    log.Println("Log Entry in JSON format:")
    log.Println(string(logEntryJSON))

    // Your application logic here
    log.Println("OpenTelemetry is set up and running!")
}
