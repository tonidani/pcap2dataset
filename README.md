# PCAP AI Dataset Generator 🚀

A lightweight tool to generate AI training datasets from PCAP files and Suricata alert logs to classify packets into attacks.

## 🛠 Features

- Converts PCAP traffic into structured datasets
- Supports Suricata (eve.json) - Future Wazuh (alerts.json), and Custom alert formats
- Optional normalization of IPs, ports, protocols for AI model training
- Outputs: CSV, JSON, or Parquet
- Lightweight Docker + Docker Compose setup

## 📂 Project Structure

```
project/
├── data/                     # Place your PCAP files and alerts here
├── Dockerfile                 # Dockerfile to build the container
├── docker-compose.yml         # Easy container orchestration
├── pcap2dataset.py  # Main script
├── README.md                  # Documentation
```

## 🐳 Docker Setup

### 1. Build the Docker Image

```bash
docker-compose build
```

### 2. Run the Container

```bash
docker-compose run pcap_2_dataset_generator
```

You will land inside a bash shell in `/data` inside the container.

## 🚀 Using the Dataset Generator

After entering the container, you can run:

```bash
python3 /app/pcap2dataset.py \
  --pcap /data/your_file.pcap \
  --alerts /data/your_alerts.json \
  --output name_of_otuput \
  --alert-format suricata \
  --normalize \
  --output-format parquet
```

### CLI Parameters Explained:
- `--pcap` → Path to the PCAP file inside `/data`
- `--alerts` → Path to the EVE.json, alerts.json, or custom alerts
- `--output` → Output file base name (without extension)
- `--alert-format` → Choose between `suricata`, `wazuh`, or `custom`
- `--custom-mapping` → Required if using `custom` format (path to mapping.json)
- `--normalize` → Normalize features (IPs/ports/protocol) for AI
- `--output-format` → Choose between `csv`, `json`, or `parquet`

## 📦 The `/data` Folder

- Mounts automatically to your local `./data`
- Place your PCAP files and alert files inside it
- The output datasets will also be saved here

Example structure:

```
project/
└── data/
    ├── test.pcap
    ├── eve.json
    ├── output_dataset.parquet
```

## 📋 Supported Alert Formats

| Source   | Format      |
|:---------|:------------|
| Suricata | eve.json     |
| Wazuh    | alerts.json  |
| Custom   | any JSON + mapping |

## 🧩 Custom Mapping Example

For Custom alert formats, you need a `mapping.json` like:

```json
{
  "src_ip": "src_ip",
  "dst_ip": "dst_ip",
  "src_port": "src_port",
  "dst_port": "dst_port",
  "timestamp": "timestamp",
  "alert": "alert",
  "attack_type": "attack_type",
  "severity": "severity",
  "payload": "payload",
  "payload_printable": "payload_printable",
  "flow_id": "flow_id",
  "pcap_cnt": "pcap_cnt",
  "direction": "direction",
  "app_proto": "app_proto",
  "flow_pkts_toserver": "flow_pkts_toserver",
  "flow_pkts_toclient": "flow_pkts_toclient",
  "flow_bytes_toserver": "flow_bytes_toserver",
  "flow_bytes_toclient": "flow_bytes_toclient",
  "flow_start": "flow_start",
  "stream": "stream",
  "pcap_filename": "pcap_filename"
}
```

- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `alert`, `timestamp` are mapped dynamically.

## 📈 Normalized Dataset Example (IDS Mode)

| timestamp        | src_ip    | dst_ip    | src_port | dst_port | protocol | frame_len | ttl | iat                 | http_method | http_uri | dns_qry_name | dns_qry_type | payload_entropy | ip_len | ip_flags | ip_dsfield | tcp_retrans | tcp_dup_ack | tcp_bytes_flight | frame_no | frame_delta | tcp_flag_fin | tcp_flag_syn | tcp_flag_rst | tcp_flag_psh | tcp_flag_ack | tcp_flag_urg | tcp_flag_ece | tcp_flag_cwr | label | alert                                                                 | attack_type                       | severity | flow_id             | pcap_cnt | direction  | flow_pkts_toserver | flow_pkts_toclient | flow_bytes_toserver | flow_bytes_toclient | flow_start                       | app_proto | stream | pcap_filename |
|------------------|-----------|-----------|----------|----------|----------|-----------|-----|---------------------|-------------|----------|--------------|--------------|-----------------|--------|----------|------------|-------------|-------------|------------------|----------|-------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------|-------|-----------------------------------------------------------------------|-----------------------------------|----------|---------------------|----------|------------|--------------------|--------------------|---------------------|---------------------|----------------------------------|-----------|--------|---------------|
| 1745110951.30714 | 10.0.0.1  | 10.0.0.5  | 44610    | 443      | TCP      | 74        | 63  | 0.0008890628814697  |             |          |              |              | 0               | 60     | 0x02     | 0x00       |             |             | 32               | 0.000889 | 0           | 1            | 0            | 0            | 0            | 0            | 0            | 0            | 1            |       | SURICATA STREAM reassembly sequence GAP -- missing packet(s)          | Generic Protocol Command Decode   | 3        | 2163594780329286    | 96       | to_server  | 11                 | 10                 | 1562                | 4039                | 2025-04-20T01:02:31.307143+0000 | tls       | 0      |               |


## ⚡ Quickstart Summary

```bash
# Build container
docker-compose build

# Start container
docker-compose up -d

# Inside container: run generator
python3 /app/pcap2dataset.py --pcap /data/test.pcap --alerts /data/eve.json --output /data/output --alert-format suricata --normalize --output-format csv
```

## 🧠 Tips

- Use correct timestamps in alert files to match packets accurately.
- Normalization is highly recommended for Machine Learning training.
- Payload-based datasets are heavier but capture more attack fingerprints.

## 📜 License

MIT License – Free to use and adapt.

Made with ❤️ by Your Team.
