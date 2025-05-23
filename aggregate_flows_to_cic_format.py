
import pandas as pd


def aggregate_flows_to_cic_format(input_csv, output_csv='cic_flows.csv'):
    df = pd.read_csv(input_csv)

    # Convert timestamp
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')

    # Create flow ID
    df['flow_id'] = (
        df['src_ip'].astype(str) + "_" + df['dst_ip'].astype(str) + "_" +
        df['src_port'].astype(str) + "_" + df['dst_port'].astype(str) + "_" +
        df['protocol'].astype(str)
    )

    # Group by flow
    grouped = df.groupby('flow_id').agg({
        'timestamp': ['min', 'max'],
        'frame_len': ['count', 'sum', 'mean', 'std'],
        'iat': ['mean', 'std', 'max', 'min'],
        'tcp_flag_syn': 'sum',
        'tcp_flag_ack': 'sum',
        'tcp_flag_psh': 'sum',
        'tcp_flag_fin': 'sum',
        'tcp_flag_rst': 'sum',
        'payload_entropy': 'mean',
        'alert': lambda x: x.dropna().unique()[0] if len(x.dropna()) > 0 else 'Benign'
    }).reset_index()

    # Flatten multiindex columns
    grouped.columns = ['_'.join(col).strip('_') for col in grouped.columns]

    # Add CIC-IDS style column
    grouped['Flow Duration'] = (
        grouped['timestamp_max'] - grouped['timestamp_min']
    ).dt.total_seconds() * 1000

    # Rename columns
    grouped.rename(columns={
        'frame_len_count': 'Total Fwd Packets',
        'frame_len_sum': 'Total Length of Fwd Packets',
        'frame_len_mean': 'Fwd Packet Length Mean',
        'frame_len_std': 'Fwd Packet Length Std',
        'iat_mean': 'Flow IAT Mean',
        'iat_std': 'Flow IAT Std',
        'iat_max': 'Flow IAT Max',
        'iat_min': 'Flow IAT Min',
        'tcp_flag_syn_sum': 'SYN Flag Count',
        'tcp_flag_ack_sum': 'ACK Flag Count',
        'tcp_flag_psh_sum': 'Fwd PSH Flags',
        'tcp_flag_fin_sum': 'FIN Flag Count',
        'tcp_flag_rst_sum': 'RST Flag Count',
        'payload_entropy_mean': 'Avg Payload Entropy',
        'alert_<lambda>': 'Label'  # <-- poprawka tutaj
    }, inplace=True)

    # Label: Malicious if not Benign
    grouped['Label'] = grouped['Label'].apply(lambda x: 'Malicious' if x != 'Benign' else 'Benign')

    grouped.to_csv(output_csv, index=False)
    print(f"[INFO] Flow-level CSV saved to: {output_csv}")
