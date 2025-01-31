import dns.resolver
import sys


def get_ns_records(domain):
    """
    Fetch NS (Name Server) records for a given domain.

    Args:
        domain (str): The domain name to query for NS records.

    Returns:
        list: A list of NS records as strings. Returns an empty list if no records are found or if an error occurs.

    Exceptions:
        Handles the following exceptions:
        - dns.resolver.NoAnswer: No answer was found for the query.
        - dns.resolver.NXDOMAIN: The domain does not exist.
        - dns.resolver.LifetimeTimeout: The query timed out.
        - Exception: Any other exceptions that may occur during the query.
    """
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
    """
    Infer the parent domain from a given subdomain.

    This function takes a subdomain as input and returns the parent domain by
    removing the first label from the subdomain. If the subdomain consists of
    only one or two labels, the function returns None.

    Args:
        subdomain (str): The subdomain from which to infer the parent domain.

    Returns:
        str or None: The parent domain if the subdomain has more than two labels,
        otherwise None.
    """
    parts = subdomain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[1:])
    return None


def check_vulnerability(subdomain, parent_domain=None):
    """
    Check DNS takeover vulnerability for a given subdomain.
    This function performs several checks to determine if a subdomain
    is vulnerable to DNS takeover, particularly focusing on AWS name servers.
    Args:
        subdomain (str): The subdomain to check for vulnerability.
        parent_domain (str, optional): The parent domain of the subdomain.
        If not provided, it will be inferred.
    Returns:
        None: The function prints the results of the checks and does not return any value.
    Steps:
        1. Infer the parent domain if not provided.
        2. Retrieve NS records for the subdomain.
        3. Retrieve NS records for the parent domain.
        4. Verify if the subdomain is delegated separately from the parent domain.
        5. Check if the NS servers belong to AWS.
        6. Check if the subdomain is resolving properly.
    Notes:
        - If AWS NS are detected, additional manual checks in AWS Route 53 may be required.
        - The function handles various DNS resolution exceptions to provide detailed feedback.
    """
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <subdomain> [parent_domain]")
        sys.exit(1)

    subdomain = sys.argv[1]
    parent_domain = sys.argv[2] if len(sys.argv) > 2 else None

    check_vulnerability(subdomain, parent_domain)
