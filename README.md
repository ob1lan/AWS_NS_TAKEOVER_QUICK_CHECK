# DNS Takeover Checker

## Overview

The DNS Takeover Checker is a Python script that checks whether a subdomain is vulnerable to a DNS zone takeover, particularly focusing on orphaned Route 53 delegations. It verifies whether the subdomain:

- Has distinct NS (Name Server) records separate from its parent domain.
- Uses AWS Route 53 Name Servers, which could indicate potential orphaned delegations.
- Properly resolves or returns SERVFAIL, a key indicator of DNS misconfiguration.
- If the assigned NS servers can actually resolve the subdomain, confirming if they are functioning correctly.

## Features

✔️ Automatic parent domain inference (can also be provided manually).
✔️ Identifies AWS Route 53 name servers linked to potential orphaned delegations.
✔️ Verifies if the NS servers actually resolve the subdomain.
✔️ Handles multiple DNS resolution scenarios (NXDOMAIN, SERVFAIL, timeouts).
✔️ Provides next steps for remediation if a takeover risk is detected.

## Installation

Ensure you have Python 3 installed. Then, install the required dependencies:

```
pip install dnspython
```

## Usage

### Basic Usage

Run the script by providing the subdomain to check:

```
python main.py <subdomain>
```

Example:

```
python main.py sub.example.com
```

### Specifying Parent Domain (Optional)

By default, the script infers the parent domain automatically. However, you can manually specify it:

```
python main.py <subdomain> <parent_domain>
```

Example:

```
python main.py sub.example.com example.com
```

## How It Works

The script performs the following steps:

### 1️⃣ Check NS Records for the Subdomain

- Queries NS records for the given subdomain.
- If no NS records exist, the subdomain is not delegated, so no takeover risk.

### 2️⃣ Check NS Records for the Parent Domain

- Queries NS records for the parent domain.
- This helps determine if the subdomain is delegated separately.

### 3️⃣ Verify If the Subdomain is Delegated Separately

- If the subdomain uses the same NS as the parent, it is not vulnerable.
- If the subdomain uses different NS, it could be at risk.

### 4️⃣ Detect AWS Route 53 Name Servers

- If the NS records match AWS (.awsdns- or .amazonaws.com), it could indicate a potential orphaned delegation.

### 5️⃣ Check If the Subdomain Resolves Properly

- Queries an A record for the subdomain.
- If it returns NXDOMAIN, SERVFAIL, or No Answer, it might indicate a takeover risk.

### 6️⃣ Verify If the NS Servers Can Resolve the Subdomain

- Each NS server is queried directly to see if it can resolve the subdomain.
- If none of the NS servers return a valid response, this strongly suggests an orphaned delegation.
