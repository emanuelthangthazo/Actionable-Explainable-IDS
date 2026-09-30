# AXIDS feature glossary

Measures below follow the CICFlowMeter implementation. High/low interpretations are analyst heuristics, not proof. CIC-IDS2017 feature-selection tables provide class correlates; no SHAP detail file was attached, so no AXIDS-model SHAP claims are made. Known schema caveats include the duplicate Fwd Header Length.1 column, CWR-versus-CWE naming, and TCP flag-count implementation issues.

## Destination Port
**Measures:** Destination transport-layer port identifier; unit: port number (dimensionless).
**High values:** A high port number may indicate an ephemeral or nonstandard service endpoint; port value alone does not identify an attack.
**Low values:** A low or well-known port may indicate a standard service target; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Flow Duration
**Measures:** Elapsed time from first to last packet; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: Heartbleed, DoS Hulk, DoS Slowhttptest, DoS slowloris, Infiltration, DDoS.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Total Fwd Packets
**Measures:** Count of packets in the forward direction, defined by the first packet; unit: packets.
**High values:** An unusually high value can indicate more activity or variability in the measured direction; interpret it with the other flow fields.
**Low values:** An unusually low value can indicate little activity or a short/quiet flow; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Total Backward Packets
**Measures:** Count of packets in the backward direction; unit: packets.
**High values:** An unusually high value can indicate more activity or variability in the measured direction; interpret it with the other flow fields.
**Low values:** An unusually low value can indicate little activity or a short/quiet flow; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Total Length of Fwd Packets
**Measures:** Sum of forward packet-size observations; unit: bytes, using the implementation accumulator.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** Paper-selected correlate for: BENIGN, Heartbleed, SSH-Patator, Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection, Infiltration, Bot.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Total Length of Bwd Packets
**Measures:** Sum of backward packet-size observations; unit: bytes, using the implementation accumulator.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Packet Length Max
**Measures:** Named statistic of forward packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Packet Length Min
**Measures:** Named statistic of forward packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Packet Length Mean
**Measures:** Named statistic of forward packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** Paper-selected correlate for: BENIGN, Bot.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Fwd Packet Length Std
**Measures:** Named statistic of forward packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd Packet Length Max
**Measures:** Named statistic of backward packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd Packet Length Min
**Measures:** Named statistic of backward packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** Paper-selected correlate for: BENIGN.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Bwd Packet Length Mean
**Measures:** Named statistic of backward packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd Packet Length Std
**Measures:** Named statistic of backward packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS GoldenEye, Heartbleed, DoS Hulk, DDoS.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Flow Bytes/s
**Measures:** Accumulated forward plus backward packet-size sum divided by duration; unit: bytes per second (B/s).
**High values:** An unusually high value can indicate flooding, scanning bursts, or highly active automated traffic; compare with duration and direction.
**Low values:** An unusually low value can indicate sparse activity, slow delivery, idle sessions, or a nearly empty flow; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Flow Packets/s
**Measures:** Packet count divided by whole-flow duration; unit: packets per second, with direction indicated by the feature name.
**High values:** An unusually high value can indicate flooding, scanning bursts, or highly active automated traffic; compare with duration and direction.
**Low values:** An unusually low value can indicate sparse activity, slow delivery, idle sessions, or a nearly empty flow; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Flow IAT Mean
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the whole-flow direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS GoldenEye.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Flow IAT Std
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the whole-flow direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS Hulk, DoS Slowhttptest, DDoS.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Flow IAT Max
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the whole-flow direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Flow IAT Min
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the whole-flow direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS GoldenEye.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Fwd IAT Total
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the forward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd IAT Mean
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the forward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS slowloris.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Fwd IAT Std
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the forward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd IAT Max
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the forward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd IAT Min
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the forward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS GoldenEye, DoS slowloris.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Bwd IAT Total
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the backward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd IAT Mean
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the backward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS slowloris.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Bwd IAT Std
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the backward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd IAT Max
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the backward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd IAT Min
**Measures:** Sum, mean, standard deviation, maximum, or minimum of packet inter-arrival gaps in the backward direction; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd PSH Flags
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** Paper-selected correlate for: FTP-Patator.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Bwd PSH Flags
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd URG Flags
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd URG Flags
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Header Length
**Measures:** Sum of header bytes in the indicated direction; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd Header Length
**Measures:** Sum of header bytes in the indicated direction; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Packets/s
**Measures:** Packet count divided by whole-flow duration; unit: packets per second, with direction indicated by the feature name.
**High values:** An unusually high value can indicate flooding, scanning bursts, or highly active automated traffic; compare with duration and direction.
**Low values:** An unusually low value can indicate sparse activity, slow delivery, idle sessions, or a nearly empty flow; it is not proof.
**Relevant attacks:** Paper-selected correlate for: FTP-Patator.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Bwd Packets/s
**Measures:** Packet count divided by whole-flow duration; unit: packets per second, with direction indicated by the feature name.
**High values:** An unusually high value can indicate flooding, scanning bursts, or highly active automated traffic; compare with duration and direction.
**Low values:** An unusually low value can indicate sparse activity, slow delivery, idle sessions, or a nearly empty flow; it is not proof.
**Relevant attacks:** Paper-selected correlate for: Bot, PortScan.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Min Packet Length
**Measures:** Minimum packet-size observation across both directions; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Max Packet Length
**Measures:** Maximum packet-size observation across both directions; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Packet Length Mean
**Measures:** Mean packet-size observation across both directions; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Packet Length Std
**Measures:** Standard deviation of packet-size observations; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Packet Length Variance
**Measures:** Variance of packet-size observations; unit: bytes².
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## FIN Flag Count
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## SYN Flag Count
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** Paper-selected correlate for: FTP-Patator.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## RST Flag Count
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## PSH Flag Count
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** Paper-selected correlate for: PortScan.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## ACK Flag Count
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** Paper-selected correlate for: SSH-Patator.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## URG Flag Count
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## CWE Flag Count
**Measures:** The requested name is ambiguous: the CICFlowMeter source defines CWR Flag Count, counting TCP Congestion Window Reduced flags; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## ECE Flag Count
**Measures:** Count of packets carrying the named TCP flag in the indicated direction; unit: packets/flags counted.
**High values:** An unusually high count can indicate repeated connection attempts, resets, or application data exchange, depending on the flag; inspect the sequence.
**Low values:** A low or zero count can indicate UDP traffic, a short flow, or no packets carrying that flag; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Down/Up Ratio
**Measures:** Backward packet count divided by forward packet count; unit: dimensionless ratio.
**High values:** An unusually high value can indicate more activity or variability in the measured direction; interpret it with the other flow fields.
**Low values:** An unusually low value can indicate little activity or a short/quiet flow; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Average Packet Size
**Measures:** Mean packet-size observation in the named direction or whole flow; unit: bytes per packet.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DDoS.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Avg Fwd Segment Size
**Measures:** Mean packet-size observation in the named direction or whole flow; unit: bytes per packet.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Avg Bwd Segment Size
**Measures:** Mean packet-size observation in the named direction or whole flow; unit: bytes per packet.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Header Length.1
**Measures:** Sum of header bytes in the indicated direction; unit: bytes. This is a duplicate of Fwd Header Length in the CSV/schema, not a distinct measurement.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Avg Bytes/Bulk
**Measures:** Average payload bytes in counted directional bulks; unit: bytes per bulk.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Avg Packets/Bulk
**Measures:** Average counted packets in directional bulks; unit: packets per bulk.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Fwd Avg Bulk Rate
**Measures:** Average payload bytes in counted directional bulks divided by bulk duration; unit: bytes per second.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd Avg Bytes/Bulk
**Measures:** Average payload bytes in counted directional bulks; unit: bytes per bulk.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd Avg Packets/Bulk
**Measures:** Average counted packets in directional bulks; unit: packets per bulk.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Bwd Avg Bulk Rate
**Measures:** Average payload bytes in counted directional bulks divided by bulk duration; unit: bytes per second.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Subflow Fwd Packets
**Measures:** Average directional packets or bytes per detected subflow; unit: packets or bytes per subflow, as named.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Subflow Fwd Bytes
**Measures:** Average directional packets or bytes per detected subflow; unit: packets or bytes per subflow, as named.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** Paper-selected correlate for: BENIGN, Heartbleed, SSH-Patator, Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection, Infiltration, Bot.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Subflow Bwd Packets
**Measures:** Average directional packets or bytes per detected subflow; unit: packets or bytes per subflow, as named.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Subflow Bwd Bytes
**Measures:** Average directional packets or bytes per detected subflow; unit: packets or bytes per subflow, as named.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Init_Win_bytes_forward
**Measures:** Initial TCP window value observed in the named direction; unit: bytes.
**High values:** An unusually high value can indicate more activity or variability in the measured direction; interpret it with the other flow fields.
**Low values:** An unusually low value can indicate little activity or a short/quiet flow; it is not proof of benignness.
**Relevant attacks:** Paper-selected correlate for: SSH-Patator, FTP-Patator, Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection, PortScan.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Init_Win_bytes_backward
**Measures:** Initial TCP window value observed in the named direction; unit: bytes.
**High values:** An unusually high value can indicate more activity or variability in the measured direction; interpret it with the other flow fields.
**Low values:** An unusually low value can indicate little activity or a short/quiet flow; it is not proof of benignness.
**Relevant attacks:** Paper-selected correlate for: Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## act_data_pkt_fwd
**Measures:** Count of forward packets carrying at least one byte of data; unit: packets.
**High values:** An unusually high value can indicate more activity or variability in the measured direction; interpret it with the other flow fields.
**Low values:** An unusually low value can indicate little activity or a short/quiet flow; it is not proof of benignness.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## min_seg_size_forward
**Measures:** Minimum forward segment/header-size value maintained by the implementation; unit: bytes.
**High values:** An unusually high value can indicate larger transfers, server responses, sustained sessions, or bulk traffic; floods and data movement require corroborating evidence.
**Low values:** An unusually low value can indicate probes, failed handshakes, keep-alive fragments, sparse control traffic, or empty/short flows; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Active Mean
**Measures:** Statistic of active or idle period durations; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS Slowhttptest, Infiltration.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Active Std
**Measures:** Statistic of active or idle period durations; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Active Max
**Measures:** Statistic of active or idle period durations; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Active Min
**Measures:** Statistic of active or idle period durations; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** Paper-selected correlate for: DoS Slowhttptest.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt https://www.scitepress.org/papers/2018/66398/66398.pdf

## Idle Mean
**Measures:** Statistic of active or idle period durations; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Idle Std
**Measures:** Statistic of active or idle period durations; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Idle Max
**Measures:** Statistic of active or idle period durations; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt

## Idle Min
**Measures:** Statistic of active or idle period durations; unit: microseconds (µs).
**High values:** An unusually high value can indicate long-lived, delayed, or bursty timing; in slow attacks it may reflect held connections, but it is not proof.
**Low values:** An unusually low value can indicate tightly spaced packets or short transactions, as seen in bursts, scans, or automated requests; it is not proof.
**Relevant attacks:** No class-specific evidence found.
**Source:** https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt
