# Dataset — CIC-IDS2017

The raw dataset file `CICIDS2017_Combined.csv` is **not included** in this
repository due to its size (~921 MB, exceeding GitHub's file size limits).

## How to obtain the dataset

The project uses the **CIC-IDS-2017** dataset published by the Canadian
Institute for Cybersecurity (CIC) at the University of New Brunswick.

> **Download source:** *(link to be filled in)*
>
> You are looking for the pre-processed CSV files (the flow-level features,
> not the raw PCAP captures). Combine all per-day CSV files into a single
> file named `CICIDS2017_Combined.csv` and place it in this `data/` directory.

## Dataset structure

Once downloaded, the combined CSV should have:

- **Rows:** ~2.83 million network flows
- **Columns:** 79 (78 numeric flow features + 1 `Label` column)
- **Classes:** 15 (1 benign + 14 attack types)

| Label | Description |
|---|---|
| BENIGN | Normal background traffic |
| DDoS | Distributed Denial of Service |
| DoS Hulk | HTTP flood via Hulk tool |
| DoS GoldenEye | DoS via GoldenEye tool |
| DoS Slowhttptest | Slow HTTP test attack |
| DoS slowloris | Slowloris DoS |
| PortScan | Network port scanning |
| Bot | Botnet C2 communication |
| FTP-Patator | FTP brute-force (Patator) |
| SSH-Patator | SSH brute-force (Patator) |
| Web Attack – Brute Force | HTTP brute-force login |
| Web Attack – XSS | Cross-site scripting |
| Web Attack – Sql Injection | SQL injection |
| Heartbleed | TLS Heartbleed exploit |
| Infiltration | Network infiltration |

## Preprocessing

The pipeline (`preprocessing/preprocessing.py`) applies the following
steps automatically at runtime:

1. Strip whitespace from column names and label values
2. Replace `Inf`/`-Inf` with `NaN`
3. Drop rows with `NaN` values (~2,867 rows)
4. Drop exact duplicate rows (~307,078 rows)
5. Label-encode the `Label` column (0–14)

After cleaning: **2,520,798 rows** retained across 15 classes.
The 80/20 stratified split produces ~2,016,638 training rows and ~504,160
test rows.
