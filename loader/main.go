package main

import (
    "fmt"
    ebpf "github.com/cilium/ebpf"
    "log"
)

func main() {
    spec, err := ebpf.LoadCollectionSpec("detectors/syscall.o")
    if err != nil {
        log.Fatal(err)
    }
    
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("✅ eBPF Rootkit Detector ARMED")
    select {} // Run forever
}

