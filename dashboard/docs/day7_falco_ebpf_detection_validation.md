# Day 7 - Falco eBPF Detection Validation

## Environment
- OS: Kali Linux Rolling
- Kernel: 7.1.5+kali-amd64
- Falco: 0.45.2
- Engine: modern_ebpf
- Service: falco-modern-bpf.service

## Configuration
Falco loads rules from falco_rules.yaml, falco_rules.local.yaml and rules.d.
Custom test rule: /etc/falco/rules.d/soc_file_write_test.yaml

## Validation
1. Verified Falco service and Modern eBPF configuration.
2. Inspected loaded BPF programs and kernel attachments using bpftool.
3. Confirmed syscall event source was enabled.
4. Successfully validated all three rule files.
5. Restarted Falco service successfully.
6. Generated a controlled file-write event.

## Detection Evidence
```text
Warning SOC TEST ALERT: File write detected
file=/tmp/soc-falco-test
user=chetan
process=zsh
container_id=host
```

## Result
PASS - Local Falco eBPF detection verified. The controlled file-write event matched the custom rule and generated a WARNING alert.

## Scope and Limitations
- Local Falco event capture and custom-rule detection verified.
- Kafka forwarding and end-to-end Grafana ingestion are not yet verified.
