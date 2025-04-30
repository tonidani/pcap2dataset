from typing import List, Dict, Any, Optional
import argparse
import json
from enum import Enum
from datetime import datetime
import pandas as pd
import subprocess
from pathlib import Path
import gc
import math
import collections
import ipaddress  # for safe IP parsing
import numpy as np  # for numerical transformations


import pyarrow as pa
import pyarrow.parquet as pq

class AlertFormat(Enum):
    SURICATA = 'suricata'
    WAZUH    = 'wazuh'
    CUSTOM   = 'custom'

    @staticmethod
    def list() -> List[str]:
        return [e.value for e in AlertFormat]

class DatasetMode(Enum):
    FLOW         = 'flow'
    FLOW_PAYLOAD = 'flow_payload'
    IDS          = 'ids'

    @staticmethod
    def list() -> List[str]:
        return [e.value for e in DatasetMode]

class OutputFormat(Enum):
    CSV     = 'csv'
    JSON    = 'json'
    PARQUET = 'parquet'

    @staticmethod
    def list() -> List[str]:
        return [e.value for e in OutputFormat]



def safe_ip_to_int(x: Any) -> int:
    """
    Safely convert IPv4 string to integer. Return 0 for NaN, non-strings or invalid IPs.
    """
    if pd.isna(x):
        return 0
    if not isinstance(x, str) or x.count('.') != 3:
        return 0
    try:
        return int(ipaddress.ip_address(x))
    except Exception:
        return 0

def load_alerts(
    alert_file: str,
    fmt: AlertFormat = AlertFormat.SURICATA,
    custom_mapping: Optional[Dict[str, Any]] = None
) -> Dict[int, List[Dict[str, Any]]]:
    print(f"[INFO] Loading alerts ({fmt.value}) from {alert_file}")
    alerts_raw: List[Dict[str, Any]] = []
    with open(alert_file) as f:
        for line in f:
            try:
                evt = json.loads(line)
                alert: Dict[str, Any] = {}
                if fmt == AlertFormat.SURICATA and 'alert' in evt:
                    flow = evt.get('flow', {})
                    alert = {
                        'src_ip': evt.get('src_ip'),
                        'dst_ip': evt.get('dest_ip'),
                        'src_port': evt.get('src_port'),
                        'dst_port': evt.get('dest_port'),
                        'timestamp': datetime.strptime(evt['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z"),
                        'alert': evt['alert']['signature'],
                        'attack_type': evt['alert'].get('category', 'unknown'),
                        'severity': evt['alert'].get('severity', -1),
                        'payload': evt.get('payload'),
                        'payload_printable': evt.get('payload_printable'),
                        'flow_id': evt.get('flow_id'),
                        'pcap_cnt': evt.get('pcap_cnt'),
                        'direction': evt.get('direction'),
                        'app_proto': evt.get('app_proto'),
                        'flow_pkts_toserver': flow.get('pkts_toserver'),
                        'flow_pkts_toclient': flow.get('pkts_toclient'),
                        'flow_bytes_toserver': flow.get('bytes_toserver'),
                        'flow_bytes_toclient': flow.get('bytes_toclient'),
                        'flow_start': flow.get('start'),
                        'stream': evt.get('stream'),
                        'pcap_filename': evt.get('pcap_filename')
                    }
                elif fmt == AlertFormat.WAZUH and 'rule' in evt:
                    alert = {
                        'src_ip': evt.get('data', {}).get('srcip'),
                        'dst_ip': evt.get('data', {}).get('dstip'),
                        'timestamp': datetime.strptime(evt['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ"),
                        'alert': evt['rule']['description'],
                        'attack_type': None,
                        'severity': None,
                        'payload': None,
                        'payload_printable': None
                    }
                elif fmt == AlertFormat.CUSTOM:
                    if not custom_mapping:
                        raise ValueError("Custom mapping required for CUSTOM format.")
                    alert = {
                        'src_ip': evt.get(custom_mapping['src_ip']),
                        'dst_ip': evt.get(custom_mapping['dst_ip']),
                        'src_port': evt.get(custom_mapping['src_port']),
                        'dst_port': evt.get(custom_mapping['dst_port']),
                        'alert': evt.get(custom_mapping['alert'], 'benign'),
                        'timestamp': None,
                        'attack_type': None,
                        'severity': None,
                        'payload': None,
                        'payload_printable': None
                    }
                    tv = evt.get(custom_mapping['timestamp'])
                    if tv:
                        try:
                            alert['timestamp'] = datetime.strptime(tv, "%Y-%m-%dT%H:%M:%S.%fZ")
                        except:
                            alert['timestamp'] = datetime.utcfromtimestamp(float(tv))
                if alert:
                    alerts_raw.append(alert)
            except Exception as e:
                print(f"[WARN] Failed to parse alert: {e}")
                continue

    alerts_map: Dict[int, List[Dict[str, Any]]] = {}
    for a in alerts_raw:
        ts = a.get('timestamp')
        key = int(ts.timestamp()) if ts else 0
        alerts_map.setdefault(key, []).append(a)

    print(f"[INFO] Loaded {len(alerts_raw)} alerts into {len(alerts_map)} bins")
    return alerts_map


def process_streaming(
    pcap: str,
    alerts_map: Dict[int, List[Dict[str, Any]]],
    mode: DatasetMode,
    normalize: bool,
    out_fmt: OutputFormat,
    base: str,
    out_dir: str = '/data',
    batch_size: int = 10000
):
    ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    out_path = Path(out_dir) / f"{base}_{ts_str}.{out_fmt.value}"

    first = True
    jf = None
    pw = None
    total_rows = 0
    if out_fmt == OutputFormat.JSON:
        jf = open(out_path, 'w', buffering=2**20)

    base_fields = [
        '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst',
        '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', '_ws.col.Protocol',
        '-e', 'frame.len', '-e', 'ip.ttl', '-e', 'tcp.flags',
        '-e', 'tcp.window_size_value', '-e', 'tcp.seq', '-e', 'tcp.ack'
    ]
    extra_fields = []
    if mode in (DatasetMode.FLOW_PAYLOAD, DatasetMode.IDS):
        extra_fields = [
            '-e', 'http.request.method', '-e', 'http.request.uri',
            '-e', 'dns.qry.name', '-e', 'dns.qry.type',
            '-e', 'data.text'
        ]
    ids_fields = []
    if mode == DatasetMode.IDS:
        ids_fields = [
            '-e', 'ip.len', '-e', 'ip.flags', '-e', 'ip.dsfield',
            '-e', 'tcp.analysis.retransmission', '-e', 'tcp.analysis.duplicate_ack',
            '-e', 'tcp.analysis.bytes_in_flight', '-e', 'frame.number',
            '-e', 'frame.time_delta'
        ]

    fields = base_fields + extra_fields + ids_fields
    cmd = ['tshark', '-r', pcap, '-T', 'fields'] + fields + [
        '-E', 'header=y', '-E', 'separator=\t', '-o',
        'tcp.desegment_tcp_streams:false'
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    header = proc.stdout.readline().rstrip('\n').split('\t')
    reader = pd.read_csv(proc.stdout, names=header, sep='\t',
                         chunksize=batch_size, engine='python')

    name_map = {
        'frame.time_epoch': 'timestamp', 'ip.src': 'src_ip',
        'ip.dst': 'dst_ip', 'tcp.srcport': 'src_port',
        'tcp.dstport': 'dst_port', '_ws.col.Protocol': 'protocol',
        'frame.len': 'frame_len', 'ip.ttl': 'ttl',
        'tcp.flags': 'tcp_flags', 'tcp.window_size_value': 'tcp_win',
        'tcp.seq': 'tcp_seq', 'tcp.ack': 'tcp_ack',
        'http.request.method': 'http_method', 'http.request.uri': 'http_uri',
        'dns.qry.name': 'dns_qry_name', 'dns.qry.type': 'dns_qry_type',
        'data.text': 'raw_payload', 'ip.len': 'ip_len', 'ip.flags': 'ip_flags',
        'ip.dsfield': 'ip_dsfield', 'tcp.analysis.retransmission': 'tcp_retrans',
        'tcp.analysis.duplicate_ack': 'tcp_dup_ack',
        'tcp.analysis.bytes_in_flight': 'tcp_bytes_flight',
        'frame.number': 'frame_no', 'frame.time_delta': 'frame_delta'
    }

    for chunk in reader:
        chunk.rename(columns=name_map, inplace=True)
        chunk['timestamp'] = pd.to_numeric(chunk['timestamp'], errors='coerce')
        chunk['iat'] = chunk['timestamp'].diff().fillna(0)

        def entropy(s: Any) -> float:
            if not isinstance(s, str) or not s:
                return 0.0
            b = s.encode('utf-8', errors='ignore')
            cnt = collections.Counter(b)
            L = len(b)
            e = 0.0
            for c in cnt.values():
                p = c / L
                e -= p * math.log2(p)
            return e

        if 'raw_payload' in chunk:
            chunk['payload_entropy'] = chunk['raw_payload'].apply(entropy).fillna(0)

        flags = chunk['tcp_flags'].fillna('0').apply(lambda x: int(x, 0))
        for bit, name in [
            (1,'fin'), (2,'syn'), (4,'rst'), (8,'psh'),
            (16,'ack'), (32,'urg'), (64,'ece'), (128,'cwr')
        ]:
            chunk[f'tcp_flag_{name}'] = ((flags & bit) > 0).astype(int)
        chunk.drop(columns=['tcp_flags'], errors='ignore', inplace=True)

        chunk['bin'] = chunk['timestamp'].round().astype('Int64')

        # merge alerts
        labels: List[int] = []
        alert_cols = [
            'alert','attack_type','severity','flow_id','pcap_cnt','direction',
            'flow_pkts_toserver','flow_pkts_toclient',
            'flow_bytes_toserver','flow_bytes_toclient',
            'flow_start','app_proto','stream','pcap_filename'
        ]
        alert_vals = {col: [] for col in alert_cols}

        for _, row in chunk.iterrows():
            key = int(row['bin']) if pd.notna(row['bin']) else 0
            matched = [
                a for a in alerts_map.get(key, [])
                if ((row['src_ip']==a['src_ip'] and row['dst_ip']==a['dst_ip'])
                    or (row['src_ip']==a['dst_ip']
                        and row['dst_ip']==a['src_ip']))
                and ((row.get('src_port')==a.get('src_port'))
                     or (row.get('dst_port')==a.get('dst_port')))
            ]
            if matched:
                a = matched[0]
                labels.append(1)
                for col in alert_cols:
                    alert_vals[col].append(a.get(col))
            else:
                labels.append(0)
                for col in alert_cols:
                    alert_vals[col].append(None)

        chunk['label'] = labels
        for col in alert_cols:
            chunk[col] = alert_vals[col]

        # normalize
        if normalize:
            proto_map = {'TCP':1, 'UDP':2, 'SCTP':3, 'ICMP':4, 'Other':5}
            chunk['protocol'] = chunk['protocol'].map(proto_map).fillna(0).astype(int)
            for ip_col in ['src_ip', 'dst_ip']:
                chunk[ip_col] = chunk[ip_col].apply(safe_ip_to_int)
            chunk['src_port'] = chunk['src_port'].fillna(0).astype(int)
            chunk['dst_port'] = chunk['dst_port'].fillna(0).astype(int)

            chunk['frame_len'] = pd.to_numeric(chunk['frame_len'], errors='coerce').fillna(0) / 65535
            # TTL w [0,1]
            chunk['ttl'] = pd.to_numeric(chunk['ttl'], errors='coerce').fillna(0) / 255
            # inter-arrival time: log scale, potem norm do max w partii
            chunk['iat'] = np.log1p(chunk['iat'].fillna(0))
            max_iat = chunk['iat'].max()
            if max_iat > 0:
                chunk['iat'] = chunk['iat'] / max_iat
            # port [0,1]
            chunk['src_port'] = chunk['src_port'] / 65535
            chunk['dst_port'] = chunk['dst_port'] / 65535

            ts = pd.to_datetime(chunk['timestamp'], unit='s', errors='coerce')
            chunk['hour'] = ts.dt.hour.fillna(0) / 23
            chunk['weekday'] = ts.dt.weekday.fillna(0) / 6

            # one-hot encoding for http_method
            if 'http_method' in chunk.columns:
                http_d = pd.get_dummies(chunk['http_method'], prefix='http')
                chunk = pd.concat([chunk, http_d], axis=1)

        # select columns
        cols = [
            'timestamp','src_ip','dst_ip','src_port','dst_port',
            'protocol','frame_len','ttl','iat'
        ]
        if mode in (DatasetMode.FLOW_PAYLOAD, DatasetMode.IDS):
            cols += ['http_method','http_uri',
                     'dns_qry_name','dns_qry_type','payload_entropy']
        if mode == DatasetMode.IDS:
            cols += [
                'ip_len','ip_flags','ip_dsfield','tcp_retrans','tcp_dup_ack',
                'tcp_bytes_flight','frame_no','frame_delta'
            ]
        cols += [f'tcp_flag_{n}' for n in
                 ['fin','syn','rst','psh','ack','urg','ece','cwr']]
        cols += ['label'] + alert_cols
        if mode == DatasetMode.FLOW_PAYLOAD:
            cols += ['payload','payload_printable']

        data = chunk[cols]
        if out_fmt == OutputFormat.CSV:
            data.to_csv(out_path,
                        mode='w' if first else 'a',
                        header=first,
                        index=False)
        elif out_fmt == OutputFormat.JSON:
            data.to_json(jf,
                         orient='records',
                         lines=True)
        else:
            table = pa.Table.from_pandas(data)
            if pw is None:
                pw = pq.ParquetWriter(out_path, table.schema)
            pw.write_table(table)

        total_rows += len(data)
        first = False
        print(f"[INFO] Wrote {len(data)} rows (total {total_rows})", end='\r')

        del chunk, data, flags, labels, alert_vals
        gc.collect()

    if jf:
        jf.close()
    if pw:
        pw.close()

    print(f"\n[INFO] Completed: {out_path} (rows {total_rows})")


def main():
    parser = argparse.ArgumentParser(
        description="Streaming PCAP to AI Dataset Generator"
    )
    parser.add_argument('--pcap', required=True, help="Path to PCAP file")
    parser.add_argument(
        '--alerts', required=True,
        help="Path to alerts JSON (Suricata EVE or others)"
    )
    parser.add_argument(
        '--output', required=True,
        help="Base output path without extension"
    )
    parser.add_argument(
        '--alert-format', choices=AlertFormat.list(), default='suricata'
    )
    parser.add_argument(
        '--mode', choices=DatasetMode.list(), default='flow'
    )
    parser.add_argument(
        '--output-format', choices=OutputFormat.list(), default='csv'
    )
    parser.add_argument(
        '--normalize', action='store_true',
        help="Normalize IPs and protocols"
    )
    parser.add_argument(
        '--batch-size', type=int, default=10000,
        help="Packets per batch to perform streaming processing (default: 10000)"
    )
    args = parser.parse_args()

    fmt = AlertFormat(args.alert_format)
    alerts_map = load_alerts(args.alerts, fmt)

    process_streaming(
        pcap=args.pcap,
        alerts_map=alerts_map,
        mode=DatasetMode(args.mode),
        normalize=args.normalize,
        out_fmt=OutputFormat(args.output_format),
        base=args.output,
        out_dir='/data',
        batch_size=args.batch_size
    )

if __name__ == '__main__':
    main()
