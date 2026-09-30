# AXIDS mitigations

Actions are defensive and operational. Severity reflects likely real-world impact, while CIC-IDS2017 labels remain dataset-specific.

## DoS Hulk
**Severity:** high — HTTP request floods can consume web-server capacity and reduce availability.
**Actions:**
- Apply per-source and global HTTP rate limits.
- Put the service behind a reverse proxy or WAF with connection controls.
- Use caching for safe repeatable responses to reduce origin work.
- Tune Apache worker, keep-alive, and timeout settings.
- Prepare upstream filtering or CDN/DDoS-provider escalation.
- Load-test the service and document safe saturation limits.
**Monitoring:** Monitor request rate, concurrent connections, latency, 4xx/5xx responses, and changes in Flow Duration or packet-rate distributions.
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://attack.mitre.org/techniques/T1499/ https://www.cisa.gov/news-events/news/understanding-denial-service-attacks

## DoS GoldenEye
**Severity:** high — Application-layer request pressure can exhaust web workers and deny legitimate access.
**Actions:**
- Rate-limit repeated requests by source and session.
- Use WAF rules and reverse-proxy connection limits.
- Cache static and idempotent responses where appropriate.
- Tune worker pools, keep-alive, and request timeouts.
- Use autoscaling or protected origin capacity for critical services.
- Keep an upstream filtering or CDN runbook ready.
**Monitoring:** Check HTTP request rate, worker occupancy, response latency, error rate, source concentration, and Bwd Packet Length Std/IAT shifts.
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://attack.mitre.org/techniques/T1499/ https://www.cisa.gov/news-events/news/understanding-denial-service-attacks

## DoS slowloris
**Severity:** high — Slow partial requests can hold server connections open until legitimate clients are starved.
**Actions:**
- Set finite header and body read timeouts.
- Limit concurrent connections per client and listener.
- Use reverse-proxy buffering and slow-client controls.
- Separate public-facing workers from internal administration.
- Patch and harden the web server and proxy.
- Test graceful degradation with approved defensive load tests.
**Monitoring:** Log incomplete requests, connection age, per-client concurrency, worker occupancy, and rising latency or refused connections.
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://attack.mitre.org/techniques/T1499/ https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

## DoS Slowhttptest
**Severity:** high — Low-rate incomplete requests can consume application session capacity without a large bandwidth spike.
**Actions:**
- Enforce header/body deadlines.
- Limit slow concurrent sessions and per-client connections.
- Buffer request bodies at a reverse proxy.
- Reject incomplete requests after an operationally safe timeout.
- Use WAF or managed edge protection.
- Test timeout changes against legitimate slow clients.
**Monitoring:** Watch long-lived low-rate sessions, prolonged IATs, incomplete-request counts, worker exhaustion, latency, and connection refusals.
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html https://attack.mitre.org/techniques/T1499/

## DDoS
**Severity:** high — Traffic from multiple sources can exhaust network or service capacity and make the application unavailable.
**Actions:**
- Use upstream scrubbing, CDN, or managed DDoS protection.
- Apply edge ACLs and rate limits without relying only on source IP.
- Protect DNS, network, and application tiers separately.
- Maintain failover, capacity, and ISP escalation plans.
- Preserve flow and firewall telemetry during mitigation.
- Review exposed services and remove unnecessary public endpoints.
**Monitoring:** Correlate multi-source bytes/s and packets/s with availability, latency, Flow Duration, IAT variation, and edge-provider alerts.
**Source:** https://attack.mitre.org/techniques/T1498/ https://www.cisa.gov/news-events/news/understanding-denial-service-attacks https://www.unb.ca/cic/datasets/ids-2017.html

## PortScan
**Severity:** medium — Scanning exposes services that may be targeted next, but it does not itself prove compromise.
**Actions:**
- Remove unnecessary listeners and restrict exposed ports.
- Use host and network firewalls with deny-by-default rules.
- Segment sensitive services from untrusted networks.
- Allowlist approved vulnerability scanners and maintenance windows.
- Rate-limit or block repeated unauthorized probes.
- Record and investigate scans that precede authentication or exploit activity.
**Monitoring:** Detect one source touching many destination ports or hosts, correlate firewall rejects with flow records, and review subsequent access attempts.
**Source:** https://attack.mitre.org/techniques/T1046/ https://www.unb.ca/cic/datasets/ids-2017.html

## FTP-Patator
**Severity:** high — Repeated FTP password guessing can compromise an account or trigger disruptive lockouts.
**Actions:**
- Retire cleartext FTP where feasible and use secure transfer.
- Require MFA or stronger compensating controls.
- Apply login throttling and carefully tuned lockout policies.
- Restrict FTP by network and least-privilege account permissions.
- Rotate credentials after suspected exposure.
- Alert and temporarily contain sources with confirmed abusive attempts.
**Monitoring:** Correlate FTP authentication failures and successes with source, account, time, lockouts, and unusual SYN/PSH or forward-rate patterns.
**Source:** https://attack.mitre.org/techniques/T1110/ https://attack.mitre.org/techniques/T1110/001/ https://www.cisa.gov/news-events/alerts/2018/03/27/brute-force-attacks-conducted-cyber-actors

## SSH-Patator
**Severity:** high — SSH password guessing can yield unauthorized shell access and enable follow-on compromise.
**Actions:**
- Prefer key-based authentication and require MFA.
- Disable password login where operationally possible.
- Restrict SSH to bastions, management networks, or allowlists.
- Apply connection throttling and fail2ban-style controls.
- Review authorized keys, sudo access, and dormant accounts.
- Rotate credentials and investigate any success after repeated failures.
**Monitoring:** Monitor sshd failures and successes, source spread, lockouts, key use, and post-login commands; correlate with flow window and ACK features.
**Source:** https://attack.mitre.org/techniques/T1110/ https://attack.mitre.org/techniques/T1110/001/ https://www.cisa.gov/news-events/alerts/2018/03/27/brute-force-attacks-conducted-cyber-actors

## Web Attack – Brute Force
**Severity:** high — Successful web credential guessing can expose user or administrative accounts and application data.
**Actions:**
- Require MFA for privileged and sensitive accounts.
- Apply adaptive rate limits and bot/challenge controls.
- Use breached-password screening and strong password policy.
- Protect management endpoints with network or identity restrictions.
- Tune lockouts to resist both guessing and account-lockout abuse.
- Log authentication outcomes with account, source, device, and session context.
**Monitoring:** Alert on repeated failures, distributed attempts across accounts, and failure-to-success transitions; validate application logs rather than flow data alone.
**Source:** https://attack.mitre.org/techniques/T1110/ https://www.cisa.gov/news-events/alerts/2018/03/27/brute-force-attacks-conducted-cyber-actors

## Web Attack – XSS
**Severity:** high — XSS can execute attacker-controlled script in a user context and compromise sessions or content.
**Actions:**
- Use context-aware output encoding and safe templating.
- Validate input with allowlists where business rules permit.
- Deploy a restrictive Content Security Policy.
- Set HttpOnly, Secure, and SameSite cookie attributes.
- Patch frameworks and remove unsafe DOM sinks.
- Tune WAF rules and investigate blocked requests without treating them as the only control.
**Monitoring:** Review WAF and application logs for injection indicators, CSP violations, unusual session use, and unexpected content changes.
**Source:** https://csrc.nist.gov/glossary/term/XSS https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS) https://www.unb.ca/cic/datasets/ids-2017.html

## Web Attack – Sql Injection
**Severity:** critical — SQL injection can disclose or alter sensitive records, bypass authentication, and affect database integrity or availability.
**Actions:**
- Use parameterized queries or prepared statements.
- Apply least privilege to application database accounts.
- Separate databases from public web tiers.
- Validate input and use safe ORM/query APIs.
- Patch vulnerable application components.
- Tune WAF rules and alert on database error or query anomalies.
**Monitoring:** Correlate web requests with database errors, anomalous query shapes, unusual read/write volume, authorization changes, and authentication bypass indicators.
**Source:** https://owasp.org/www-community/attacks/SQL_Injection https://owasp.org/www-project-code-review-guide/ https://www.unb.ca/cic/datasets/ids-2017.html

## Bot
**Severity:** high — A compromised host can provide persistent control, data exposure, or a platform for coordinated attacks.
**Actions:**
- Isolate suspected hosts from the network while preserving evidence.
- Block known malicious DNS, domains, and outbound destinations.
- Enforce egress filtering and restrict unnecessary protocols.
- Use EDR to remove persistence and identify the controlling process.
- Rotate credentials and tokens used on the host.
- Reimage systems when integrity cannot be established.
**Monitoring:** Look for periodic outbound connections, unusual DNS/HTTP destinations, endpoint process evidence, failed connections, and host fan-out; correlate with C2 and EDR telemetry.
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://www.cisa.gov/news-events/news/understanding-denial-service-attacks

## Infiltration
**Severity:** critical — Initial compromise followed by internal discovery can enable persistent access, lateral movement, and broader data exposure.
**Actions:**
- Segment user, server, and management networks.
- Patch internet-facing and internally exposed software.
- Use application allowlisting for downloaded or removable-media programs.
- Apply least privilege and restrict east-west administration.
- Use EDR to contain hosts and preserve forensic evidence.
- Monitor and restrict internal discovery and unusual file transfers.
**Monitoring:** Correlate suspicious downloads or exploit alerts with new persistence, east-west scans, unusual directionality, privilege changes, and outbound transfer activity.
**Source:** https://www.unb.ca/cic/datasets/ids-2017.html https://www.scitepress.org/papers/2018/66398/66398.pdf https://www.cisa.gov/topics/cyber-threats-and-advisories/malware-phishing-and-ransomware

## Heartbleed
**Severity:** critical — Remote memory disclosure can expose private keys, credentials, sessions, and protected content.
**Actions:**
- Patch or replace vulnerable OpenSSL and restart affected services.
- Inventory TLS endpoints and disable unpatched services.
- Revoke and reissue certificates and private keys.
- Rotate passwords, tokens, cookies, and other secrets in memory.
- Review logs and packet captures for exploitation indicators.
- Enable forward secrecy where supported and document the incident response.
**Monitoring:** Scan for vulnerable library versions, review TLS heartbeat activity and access logs, and treat exposed keys or credentials as compromised until rotated.
**Source:** https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability-cve-2014-0160 https://nvd.nist.gov/vuln/detail/cve-2014-0160 https://www.cve.org/CVERecord?id=CVE-2014-0160
