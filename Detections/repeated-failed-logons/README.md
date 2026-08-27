# Detection 01 - Repeated Failed Windows Logons

## Overview

This detection identifies repeated failed Windows authentication attempts within a short period of time.

The detection uses Windows Security Event ID 4625, which is generated when an account fails to log on. A single failed authentication attempt is common and does not necessarily indicate malicious activity. Multiple failures against the same account from the same source within a short time period can be more interesting from a security monitoring perspective.

For this lab, the detection threshold was configured as three or more failed authentication attempts within a five-minute window.

> The threshold of three failures is intentionally low for lab testing and should not be treated as a production recommendation.

---

## Lab Environment

The detection was developed using:

- Windows VM - monitored endpoint
- Windows Security Event Log
- Splunk Universal Forwarder
- Ubuntu Splunk Enterprise server
- Splunk Search Processing Language (SPL)

Telemetry flow:

```
Windows Endpoint
  → Windows Security Log
  → Splunk Universal Forwarder
  → Splunk Enterprise
  → SPL Detection
```

---

## Required Telemetry

### Windows Event ID 4625

Event ID 4625 records failed Windows logon attempts.

During initial testing, no 4625 events were being generated even though incorrect passwords were intentionally entered.

The Windows audit policy was checked using:

```cmd
auditpol /get /subcategory:"Logon"
```

The initial configuration returned:

```
Logon    No Auditing
```

Failed and successful logon auditing was then enabled:

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

Verification:

```cmd
auditpol /get /subcategory:"Logon"
```

Result:

```
Logon    Success and Failure
```

After enabling the audit policy, failed authentication attempts successfully generated Event ID 4625.

### Test Procedure

Controlled failed authentication attempts were generated on the Windows lab VM using:

```cmd
runas /user:Administrator cmd
```

An incorrect password was intentionally supplied several times.

This generated four Event ID 4625 events in the Windows Security log.

Splunk ingestion was verified with:

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
```

The events contained information including:

- Account name
- Logon type
- Source network address
- Failure reason
- Endpoint hostname

---

## Initial Detection

The first detection grouped failed authentication events into five-minute windows:

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count as FailedAttempts
    values(Failure_Reason) as FailureReason
    values(Logon_Type) as LogonType
    by _time host Account_Name Source_Network_Address
| where FailedAttempts >= 3
| sort - FailedAttempts
```

The detection successfully identified the four failed authentication attempts.

However, the results contained two account values:

- `Administrator`
- `WIN-FMBF3EA6U0N$`

This occurred because Splunk extracted multiple `Account_Name` values from Event ID 4625.

---

## Detection Tuning

Inspection of the raw Windows event showed that `Account_Name` was a multivalue field.

The values represented different sections of the Windows event, including the system/computer account and the account associated with the failed authentication.

For the telemetry generated in this lab, the target account was the second value.

The following SPL was used to extract it:

```spl
| eval TargetAccount=mvindex(Account_Name,1)
```

This removed the duplicate grouping and produced a single result for the targeted account.

---

## Final Detection

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| eval TargetAccount=mvindex(Account_Name,1)
| bin _time span=5m
| stats count as FailedAttempts
    values(Failure_Reason) as FailureReason
    values(Logon_Type) as LogonType
    by _time host TargetAccount Source_Network_Address
| where FailedAttempts >= 3
| sort - FailedAttempts
```

### Detection Logic

The rule identifies:

- Windows Event ID 4625
- Same target account
- Same source network address
- Three or more failures
- Within a five-minute time window

---

## Validation

### Positive Test

Four failed authentication attempts were generated within a short period.

Result:

| Field | Value |
|---|---|
| Target Account | Administrator |
| Failed Attempts | 4 |
| Source Address | 127.0.0.1 |
| Logon Type | 7 |
| Failure Reason | Unknown user name or bad password |

The detection triggered successfully.

### Negative Test

A single failed authentication attempt was generated in a separate time window.

The 4625 event appeared in Splunk, confirming that telemetry collection was working.

The detection did not return a result because the threshold of three failures was not reached.

This confirmed that the threshold logic was functioning as expected.

---

## False Positives and Tuning

Repeated authentication failures are not automatically malicious.

Possible legitimate causes include:

- Users repeatedly mistyping passwords
- Recently changed passwords
- Saved or cached credentials
- Services using outdated credentials
- Misconfigured applications
- Administrative troubleshooting

A production deployment would require baselining normal authentication behaviour before selecting an appropriate threshold.

Additional tuning could consider:

- Source IP address
- Target account
- Privileged accounts
- Logon type
- Endpoint
- Failure status/substatus codes
- Known administrative systems
- Historical authentication behaviour

---

## Limitations

The lab detection uses:

```spl
mvindex(Account_Name,1)
```

to select the target account.

This relies on the ordering of the multivalue field observed in this lab environment. A production detection should use more reliable field extraction or normalized Windows security fields rather than assuming that the target account will always appear at the same multivalue index.

The five-minute bucket approach can also split activity that crosses a bucket boundary. A production implementation could use alternative aggregation or time-window techniques depending on the required detection behaviour.

---

## Alerting

The detection was saved as a Splunk report.

The lab currently uses the Splunk Free license, which does not provide the scheduled alerting functionality required to deploy the search as a standard Splunk alert.

- **Detection status:** Validated
- **Alert status:** Not deployed due to lab licensing limitations

---

## MITRE ATT&CK

This detection can provide evidence associated with credential-access activity involving repeated password attempts.

Relevant ATT&CK technique:

- **T1110 - Brute Force**

The presence of repeated Event ID 4625 events alone does not prove that brute force activity occurred. Additional context and investigation are required before classifying the behaviour as malicious.

---

## Key Takeaways

This detection demonstrated that detection engineering depends on more than writing an SPL query.

During development, the following issues had to be identified and addressed:

- Windows was initially not auditing failed logons.
- Audit policy was enabled to generate the required telemetry.
- Event ID 4625 ingestion into Splunk was validated.
- Controlled authentication failures were generated.
- Initial detection logic produced noisy account grouping.
- Raw event fields were inspected.
- The SPL was tuned to identify the target account.
- Positive and negative tests were performed.
- Limitations and potential false positives were documented.

The exercise demonstrated the full process from telemetry generation through detection development and validation.
