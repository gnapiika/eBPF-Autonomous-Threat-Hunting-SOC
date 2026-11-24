# Falco and Kafka on Linux

Use a Linux host or WSL 2 distribution with a kernel and permissions supported by the Falco driver. Modern eBPF typically requires Linux 5.8 or newer and kernel BTF. These checks show the running kernel and whether its BTF is exposed:

```bash
uname -r
test -r /sys/kernel/btf/vmlinux && echo "Kernel BTF is readable"
falco --version
```

Use your installed Falco package configuration and service name. Check the running service and merge these settings into its configuration:

```yaml
json_output: true
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/events.json
```

Have the host owner configure directory access so Falco can write and the forwarder user can read the file. The owner can restart the installed Falco unit after the configuration change. Service names may identify the driver, for example `falco-modern-bpf.service`. On WSL 2, systemd support and eBPF compatibility depend on the distribution and running kernel.

## Safe file activity test

If the existing lab Falco configuration has no file rule, add this rule through its local rules configuration. The rule observes a write only to the lab test path.

```yaml
- rule: SOC Test File Write
  desc: Observe a write to the SOC test file
  condition: evt.type in (open, openat, openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0 and fd.name=/tmp/soc-falco-test
  output: "SOC test file opened for writing (file=%fd.name operation=%evt.type process=%proc.name pid=%proc.pid host=%evt.hostname)"
  priority: NOTICE
  tags: [soc_lab]
```

With the broker listening at the default localhost address, start the consumer in one terminal and the forwarder in another:

```bash
.venv-wsl/bin/python -m telemetry.kafka_detection_consumer
.venv-wsl/bin/python -m telemetry.falco.falco_kafka_forwarder --file /var/log/falco/events.json
```

In a third terminal run:

```bash
printf '%s\n' 'SOC telemetry test' >> /tmp/soc-falco-test
```

Verify a Falco JSON record, a Kafka offset in the forwarder terminal, and a `file_activity` event with `synthetic=False` in the consumer. The custom rule should give a low-severity `DET-004` alert with the file path. Falco only includes fields selected by the installed rules. Use authorized host activity and restrict access to the exported data.

If the broker runs on another host, make its advertised listener reachable by the Linux client and set `SOC_KAFKA_BOOTSTRAP` to that address. For local Windows Docker plus WSL, make sure the broker's advertised loopback address is reachable from the chosen WSL networking mode. A native Linux host can run both Compose and the forwarder locally.

[Falco driver support](https://falco.org/about/faq/) · [Fields available in Falco JSON](https://falco.org/docs/reference/rules/supported-fields/)
