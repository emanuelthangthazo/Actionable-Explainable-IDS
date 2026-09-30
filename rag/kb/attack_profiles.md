# AXIDS attack profiles

CIC-IDS2017 labels are assigned from timestamp, endpoints, ports, protocol, and attack schedule; the paper’s feature-selection results are correlates, not universal signatures or thresholds. “Documented” identifies evidence from the paper or cited source; “mechanism-based expectation” is a cautious interpretation of how the attack works.

## BENIGN
**Summary:** BENIGN is the normal/background class in CIC-IDS2017. It represents ordinary user activity rather than an attack mechanism.
**Flow-level signature:** No unique signature is verified (documented); use the dataset label and context rather than treating any single flow statistic as proof of benignness.
**Typical impact:** The traffic itself is intended to be normal, but mislabeled or out-of-window flows can distort IDS evaluation.
**Tools/dataset context:** The authors used B-Profile to generate benign HTTP, HTTPS, FTP, SSH, and email behavior on Monday, the normal-only day.
**MITRE ATT&CK:** None
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf

## DoS Hulk
**Summary:** DoS Hulk is an HTTP denial-of-service pattern that sends many requests to consume web-server capacity. It is a dataset scenario, not a universal fingerprint.
**Flow-level signature:** Backward packet-length variability, Flow Duration, and Flow IAT Std were selected correlates (documented); elevated request volume and repeated web flows are mechanism-based expectations. Thresholds are not verified.
**Typical impact:** Can increase latency, exhaust application resources, and prevent legitimate web requests from completing.
**Tools/dataset context:** The paper identifies Hulk among the Wednesday DoS tools used against an Ubuntu Apache server; exact settings are not verified.
**MITRE ATT&CK:** None
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf

## DoS GoldenEye
**Summary:** DoS GoldenEye is an HTTP denial-of-service scenario intended to reduce web-service availability. It repeatedly drives application-layer requests rather than defining a fixed statistical signature.
**Flow-level signature:** Bwd Packet Length Std, Flow IAT Min, Fwd IAT Min, and Flow IAT Mean were selected correlates (documented); repeated HTTP sessions and request bursts are mechanism-based expectations. Thresholds are not verified.
**Typical impact:** Can exhaust web-server workers or other application resources, causing slow responses or service denial.
**Tools/dataset context:** The paper identifies GoldenEye among the Wednesday DoS tools used against Ubuntu Apache; exact settings are not verified.
**MITRE ATT&CK:** T1499
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://attack.mitre.org/techniques/T1499/

## DoS slowloris
**Summary:** Slowloris is a low-and-slow HTTP denial of service that keeps partial connections open while sending data slowly. It consumes connection or worker capacity without requiring high bandwidth.
**Flow-level signature:** Long Flow Duration and larger Fwd IAT Min, Bwd IAT Mean, and Fwd IAT Mean are documented correlates; long-lived, low-rate, incomplete sessions are mechanism-based expectations. Thresholds are not verified.
**Typical impact:** Can occupy concurrent server resources until legitimate clients are delayed or refused.
**Tools/dataset context:** The paper identifies Slowloris as a Wednesday DoS tool used against Ubuntu Apache; exact settings are not verified.
**MITRE ATT&CK:** T1499.002
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://attack.mitre.org/techniques/T1499/002/

## DoS Slowhttptest
**Summary:** Slowhttptest is a slow HTTP denial-of-service pattern using incomplete or very slowly delivered requests. The server holds sessions open while resources remain occupied.
**Flow-level signature:** Flow Duration, Active Min, Active Mean, and Flow IAT Std were selected correlates (documented); small client segments and prolonged gaps are mechanism-based expectations. Thresholds are not verified.
**Typical impact:** Can exhaust connection/session capacity and degrade or deny web-service availability.
**Tools/dataset context:** The paper identifies Slowhttptest as a Wednesday DoS tool used against Ubuntu Apache; exact settings are not verified.
**MITRE ATT&CK:** None
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

## DDoS
**Summary:** DDoS is a distributed denial-of-service scenario in which multiple systems send traffic toward one target. Distribution increases the volume and makes source-based filtering harder.
**Flow-level signature:** Bwd Packet Length Std, Average Packet Size, Flow Duration, and Flow IAT Std were selected correlates (documented); many sources converging on one service is a mechanism-based expectation. No numeric threshold is verified.
**Typical impact:** Can exhaust network bandwidth or application resources and make the service unavailable.
**Tools/dataset context:** The authors used multiple Windows 8.1 attackers and LOIC against an Ubuntu web server on Friday; exact settings are not verified.
**MITRE ATT&CK:** T1498
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://attack.mitre.org/techniques/T1498/ https://www.cisa.gov/news-events/news/understanding-denial-service-attacks

## PortScan
**Summary:** PortScan is reconnaissance that probes hosts to discover reachable ports and services. It is usually preparation for later access rather than compromise by itself.
**Flow-level signature:** Init_Win_bytes_forward, Bwd Packets/s, and PSH Flag Count were selected correlates (documented); many short connections across destination ports are a mechanism-based expectation. Thresholds are not verified.
**Typical impact:** Reveals exposed services and helps an operator choose follow-on targets; scanning alone does not prove compromise.
**Tools/dataset context:** The authors used Nmap-based port scanning on Friday; exact scan settings are not needed to interpret an alert.
**MITRE ATT&CK:** T1046
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://attack.mitre.org/techniques/T1046/

## FTP-Patator
**Summary:** FTP-Patator is repeated FTP authentication activity associated with password guessing. The label does not establish a successful login.
**Flow-level signature:** Init_Win_bytes_forward, Fwd PSH Flags, SYN Flag Count, and Fwd Packets/s were selected correlates (documented); repeated authentication failures and short connection cycles are mechanism-based expectations. Thresholds are not verified.
**Typical impact:** Successful guessing can expose or modify files available to the account; failures can trigger lockout or service noise.
**Tools/dataset context:** The authors used Patator for FTP brute force on Tuesday; credential lists, rates, and outcomes are not verified.
**MITRE ATT&CK:** T1110.001
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://attack.mitre.org/techniques/T1110/ https://attack.mitre.org/techniques/T1110/001/

## SSH-Patator
**Summary:** SSH-Patator is repeated SSH login activity associated with password guessing. The dataset label does not prove that any credential succeeded.
**Flow-level signature:** Init_Win_bytes_forward, Subflow Fwd Bytes, Total Length of Fwd Packets, and ACK Flag Count were selected correlates (documented); repeated authentication failures and SSH session attempts are mechanism-based expectations. Thresholds are not verified.
**Typical impact:** Successful guessing can provide unauthorized account or remote-shell access and enable follow-on compromise.
**Tools/dataset context:** The authors used Patator for SSH brute force on Tuesday; credential lists, rates, and outcomes are not verified.
**MITRE ATT&CK:** T1110.001
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://attack.mitre.org/techniques/T1110/ https://attack.mitre.org/techniques/T1110/001/

## Web Attack – Brute Force
**Summary:** This class represents repeated web authentication attempts against the vulnerable web application. The class does not prove a successful login.
**Flow-level signature:** Init_Win_bytes_forward, Init_Win_bytes_backward, Subflow Fwd Bytes, and Total Length of Fwd Packets were selected for the Web Attack group (documented); repeated requests and failed-login responses are mechanism-based expectations. Thresholds are not verified.
**Typical impact:** Successful guessing can expose accounts, administrative functions, or sensitive application data.
**Tools/dataset context:** The authors used DVWA and Selenium automation for web brute force on Thursday; exact request settings are not verified.
**MITRE ATT&CK:** T1110
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://attack.mitre.org/techniques/T1110/

## Web Attack – XSS
**Summary:** XSS injects untrusted input that executes script in another user’s browser. The CIC label identifies a web-attack scenario but not a stored, reflected, or DOM subtype.
**Flow-level signature:** The Web Attack feature set included Init_Win_bytes_forward, Init_Win_bytes_backward, Subflow Fwd Bytes, and Total Length of Fwd Packets (documented); payload content is not visible in these flow features, so no unique flow signature is verified.
**Typical impact:** Can expose session data, alter page content, redirect users, or enable account compromise.
**Tools/dataset context:** The authors used DVWA and Selenium automation for XSS on Thursday; exact payloads are not verified.
**MITRE ATT&CK:** None
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://csrc.nist.gov/glossary/term/XSS

## Web Attack – Sql Injection
**Summary:** SQL injection places attacker-controlled input into a database query. The CIC label identifies the scenario but does not prove a successful database operation.
**Flow-level signature:** The Web Attack feature set included Init_Win_bytes_forward, Init_Win_bytes_backward, Subflow Fwd Bytes, and Total Length of Fwd Packets (documented); SQLi payloads are not reliably distinguishable from flow statistics, so a unique signature is not verified.
**Typical impact:** Can disclose, alter, or delete data and may bypass authentication or elevate database privileges.
**Tools/dataset context:** The authors used DVWA, a vulnerable PHP/MySQL application, on Thursday; the exact SQLi tool and payloads are not verified.
**MITRE ATT&CK:** T1190
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://owasp.org/www-community/attacks/SQL_Injection

## Bot
**Summary:** Bot is the CIC-IDS2017 label for traffic associated with the ARES botnet scenario. It indicates a dataset scenario, not a malware-family identification.
**Flow-level signature:** Subflow Fwd Bytes, Total Length of Fwd Packets, Fwd Packet Length Mean, and Bwd Packets/s were selected correlates (documented); recurring outbound connections or command-and-control-like sessions are mechanism-based expectations. No unique signature is verified.
**Typical impact:** A compromised host may lose confidentiality and control and can be used for coordinated attacks or DDoS.
**Tools/dataset context:** The authors used the Python-based ARES botnet against five Windows victims on Friday; exact commands and C2 settings are not verified.
**MITRE ATT&CK:** None
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://www.cisa.gov/news-events/news/understanding-denial-service-attacks

## Infiltration
**Summary:** Infiltration is a staged compromise scenario involving an initial infected-file or exploit stage followed by internal discovery. It is not a universal packet-level definition.
**Flow-level signature:** Subflow Fwd Bytes, Total Length of Fwd Packets, Flow Duration, and Active Mean were selected correlates (documented); multi-stage traffic and unusual east-west directionality are mechanism-based expectations. No unique signature is verified.
**Typical impact:** Can establish persistent access, enable lateral movement, and expose or disrupt additional systems.
**Tools/dataset context:** The authors documented Metasploit, Dropbox or infected removable media, and Nmap discovery on Thursday; exact exploit and file-transfer details are not verified.
**MITRE ATT&CK:** T1046
Note: T1046 reflects only the discovery/reconnaissance phase of this multi-stage scenario (post-compromise internal scanning); the initial compromise and lateral movement stages are not captured by this single technique ID.
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://attack.mitre.org/techniques/T1046/ https://www.cisa.gov/topics/cyber-threats-and-advisories/malware-phishing-and-ransomware

## Heartbleed
**Summary:** Heartbleed is a vulnerable OpenSSL heartbeat buffer over-read that can disclose process memory remotely. It is a vulnerability-driven information-disclosure event, not a generic DoS.
**Flow-level signature:** Bwd Packet Length Std, Subflow Fwd Bytes, Flow Duration, and Total Length of Fwd Packets were selected correlates (documented); repeated request/response exchanges and transferred memory-like data are mechanism-based expectations. No canonical threshold is verified.
**Typical impact:** May expose credentials, session data, private keys, and other sensitive memory, requiring key and credential replacement.
**Tools/dataset context:** The authors used Heartleech against vulnerable OpenSSL 1.0.1f on Wednesday; exact request settings are not verified.
**MITRE ATT&CK:** None
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability-cve-2014-0160 https://nvd.nist.gov/vuln/detail/cve-2014-0160
