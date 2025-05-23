import pandas as pd
import json

csv_path = '/data/2025-04-16_01-02-21.log.pcap_Flow.csv'
eve_path = '/data/2025-04-16_01-02-21.eve.json'
out_path = '/data/dane_z_labelami.csv'

# 1. Wczytaj przepływy sieciowe
df = pd.read_csv(csv_path, parse_dates=['Timestamp'])

# 2. Wyciągnij (sekunda, sygnatura) z eve.json
alert_ts, alert_sig = [], []
with open(eve_path, 'r') as f:
    for line in f:
        try:
            entry = json.loads(line)
            if entry.get('event_type') == 'alert':
                alert_ts.append(
                    pd.to_datetime(entry['timestamp']).tz_convert(None).round('S')
                )
                alert_sig.append(entry['alert']['signature'])
        except json.JSONDecodeError:
            continue

alert_df = (
    pd.DataFrame({'ts_round': alert_ts, 'signature': alert_sig})
      .drop_duplicates('ts_round')
)

# 3. Przygotuj timestamp zaokrąglony do sekundy
df['ts_round'] = df['Timestamp'].dt.round('S')

# 4. Scal przepływy z alertami
df = df.merge(alert_df, on='ts_round', how='left')

# 5. Ustaw kolumnę Label — zawsze nadpisujemy
df['Label'] = df['signature']              # sygnatura lub NaN
df['Label'].fillna('BENIGN', inplace=True) # brak dopasowania → BENING

# 6. Usuń kolumny pomocnicze
df.drop(columns=['ts_round', 'signature'], inplace=True)

# 7. Zapisz wynik
df.to_csv(out_path, index=False)
print(f"Wynik zapisano w {out_path}")
