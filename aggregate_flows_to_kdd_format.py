# -*- coding: utf-8 -*-
"""
packets_to_kdd.py
=================

Minimalny, samodzielny skrypt **jednego zadania**: z pakietowego CSV/TSV
(z kolumnami dokładnie jak w Twojej próbce) zbudować **10-kolumnowy** wektor
KDD-Cup ’99.  Żadnych zależności od poprzednich funkcji ani formatu CIC.

Wymagane kolumny w wejściowym pliku (rozszerz w razie potrzeby):

```
timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
 tcp_segment_size, tcp_flag_syn, tcp_flag_ack, tcp_flag_fin, tcp_flag_rst,
 tcp_flag_urg, attack_type
```

Jeśli nie ma `flow_id` (czasem Suricata go nie dodaje) – skrypt tworzy go
sam z 5-tupli.

Przykład uruchomienia::

    python -m packets_to_kdd in_packets.tsv kdd_subset.csv  "\t"
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict

import pandas as pd

###############################################################################
# Pomocnicze słowniki / funkcje
###############################################################################

_PORT_TO_SERVICE: Dict[int, str] = {
    20: "ftp", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 123: "ntp", 143: "imap", 161: "snmp", 443: "https",
}


def _service_from_ports(src_port: int, dst_port: int) -> str:
    """Najpierw sprawdzamy port docelowy – typowy kierunek klient → serwer."""
    return (_PORT_TO_SERVICE.get(dst_port)
            or _PORT_TO_SERVICE.get(src_port)
            or "other")


def _build_flag(syn: int, ack: int, fin: int, rst: int) -> str:
    if syn and ack and not rst:
        return "SF"  # normal finish / ongoing
    if syn and not ack:
        return "S0"  # half-open (no answer)
    if rst:
        return "REJ"  # reset
    return "OTH"     # anything else

###############################################################################
# Główna funkcja
###############################################################################

def packets_to_kdd(input_csv: str, output_csv: str, sep: str = ",") -> None:
    """Pakiety → podzbiór KDD-Cup ’99 (10 kolumn).

    Parametry
    ----------
    input_csv : str
        Ścieżka do pakietowego CSV/TSV.
    output_csv : str
        Dokąd zapisać wynik.
    sep : str, default ','
        Separator ("," dla CSV, "\t" dla TSV).
    """
    df = pd.read_csv(input_csv, sep=sep, engine="python")
    for col in ("src_port", "dst_port", "tcp_segment_size"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", errors="coerce")

    df["flow_id"] = (
            df["src_ip"].astype(str) + "_" + df["dst_ip"].astype(str) + "_"
            + df["src_port"].astype(str) + "_" + df["dst_port"].astype(str) + "_"
            + df["protocol"].astype(str)
        )

    # kierunek: pierwszy pakiet definiuje FWD (typowo klient)
    first_src = (df.sort_values("timestamp")
                   .groupby("flow_id")["src_ip"]
                   .first())
    df["is_fwd"] = df.apply(lambda r: r["src_ip"] == first_src[r["flow_id"]], axis=1)

    def _agg(g: pd.DataFrame) -> pd.Series:
        return pd.Series({
            "duration": (g["timestamp"].max() - g["timestamp"].min()).total_seconds(),
            "protocol_type": g["protocol"].iat[0].lower(),
            "service": _service_from_ports(int(g["src_port"].iat[0]), int(g["dst_port"].iat[0])),
            "src_bytes": g.loc[g["is_fwd"], "tcp_segment_size"].sum(),
            "dst_bytes": g.loc[~g["is_fwd"], "tcp_segment_size"].sum(),
            "land": int(g["src_ip"].iat[0] == g["dst_ip"].iat[0]),
            "flag": _build_flag(g["tcp_flag_syn"].sum(), g["tcp_flag_ack"].sum(),
                                 g["tcp_flag_fin"].sum(), g["tcp_flag_rst"].sum()),
            "wrong_fragment": 0,
            "urgent": int(g.get("tcp_flag_urg", 0).sum() > 0),
            "label": ('attack' if g["alert"].notna().any() else "normal"),
        })

    kdd = df.groupby("flow_id").apply(_agg).reset_index(drop=True)

    cols = [
        "duration", "protocol_type", "service", "flag", "src_bytes",
        "dst_bytes", "land", "wrong_fragment", "urgent", "label",
    ]
    kdd.to_csv(output_csv, index=False, columns=cols)
    print(f"[✔] KDD subset zapisany do → {output_csv}  (wiersze: {len(kdd)})")


packets_to_kdd('/data/tets.csv_20250522_102506.csv', '/data/kdd_subset.csv', sep=',')