import dns.resolver
import sys

def get_ns_records(domain):
    """Fetch NS records for a domain."""
    try:
        answer = dns.resolver.resolve(domain, 'NS')
        return [str(rr) for rr in answer]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.LifetimeTimeout:
        print(f"⏳ Timeout querying NS for {domain}")
        return []
    except Exception as e:
        print(f"❌ Error querying NS for {domain}: {e}")
        return []

def infer_parent_domain(subdomain):
    """Infer parent domain by removing the first label from the subdomain."""
    parts = subdomain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[1:])  # Remove first label
    return None

def check_vulnerability(subdomain, parent_domain=None):
    print(f"\n🔍 Checking DNS takeover vulnerability for: {subdomain}")

    # Infer parent domain if not provided
    if not parent_domain:
        parent_domain = infer_parent_domain(subdomain)
        if not parent_domain:
            print("❌ Unable to infer parent domain. Please provide it explicitly.")
            return

    print(f"  ➤ Using parent domain: {parent_domain}")

    # Step 1: Get NS records for the subdomain
    subdomain_ns = get_ns_records(subdomain)
    if not subdomain_ns:
        print(f"❌ No NS records found for {subdomain}. It may not be delegated.")
        return

    print(f"  ✅ Found NS records for {subdomain}: {', '.join(subdomain_ns)}")

    # Step 2: Get NS records for the parent domain
    parent_ns = get_ns_records(parent_domain)
    print(f"  ✅ Found NS records for parent domain {parent_domain}: {', '.join(parent_ns)}")

    # Step 3: Verify if the subdomain is delegated separately
    if set(subdomain_ns) == set(parent_ns):
        print("  ✅ Subdomain uses the same NS as the parent. No delegation detected.")
        return

    print(f"⚠️  {subdomain} has a different delegation from {parent_domain}, which could be a risk.")

    # Step 4: Check if the NS servers belong to AWS
    aws_ns_pattern = (".awsdns-", ".amazonaws.com")
    aws_ns_servers = [ns for ns in subdomain_ns if any(pattern in ns.lower() for pattern in aws_ns_pattern)]
    
    if aws_ns_servers:
        print(f"⚠️  Detected AWS Name Servers: {', '.join(aws_ns_servers)}")

        # Step 5: Check if the subdomain is resolving (SERVFAIL means possible orphaned delegation)
        try:
            dns.resolver.resolve(subdomain, 'A')
            print("  ✅ Subdomain resolves properly. It is not vulnerable.")
        except dns.resolver.NoAnswer:
            print(f"⚠️  No A record found for {subdomain}. This might indicate an issue.")
        except dns.resolver.NXDOMAIN:
            print(f"❌ {subdomain} does not exist in DNS.")
        except dns.resolver.LifetimeTimeout:
            print(f"⏳ Query timeout for {subdomain}, might indicate an issue.")
        except dns.resolver.NoNameservers:
            print(f"⚠️ No name servers responding for {subdomain}. Possible orphaned delegation!")

        print("\n🛠  Next step: If you have AWS credentials, manually check Route 53 for orphaned zones.")

    else:
        print("  ✅ NS records are not pointing to AWS. This subdomain is likely not vulnerable.")

# Command-line interface
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dns_takeover_check.py <subdomain> [parent_domain]")
        sys.exit(1)

    subdomain = sys.argv[1]
    parent_domain = sys.argv[2] if len(sys.argv) > 2 else None

    check_vulnerability(subdomain, parent_domain)
