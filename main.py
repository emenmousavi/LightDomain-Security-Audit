import dns.resolver

# Function to check if the domain has SPF, DKIM, and DMARC records
def check_domain_security(domain):
    # Set up the DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1

    # Check for SPF record
    try:
        spf_record = resolver.query(domain, 'TXT')
        spf_found = False
        for rdata in spf_record:
            if 'v=spf1' in rdata.strings:
                spf_found = True
                break
        if not spf_found:
            print(f"{domain} does not have an SPF record configured. Visit https://easydmarc.com/blog/how-to-create-an-spf-record/ to learn how to configure SPF.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.resolver.NoAnswer:
        print(f"No TXT record found for {domain}.")
    
    # Check for DKIM record
    try:
        dkim_record = resolver.query(f"_adsp._domainkey.{domain}", 'TXT')
        if not dkim_record:
            print(f"{domain} does not have a DKIM record configured. Visit https://easydmarc.com/blog/dkim-record-how-to-create-add-and-check-dkim-records/ to learn how to configure DKIM.")
    except dns.resolver.NoAnswer:
        print(f"No TXT record found for _adsp._domainkey.{domain}.")
    
    # Check for DMARC record
    try:
        dmarc_record = resolver.query(f"_dmarc.{domain}", 'TXT')
        dmarc_found = False
        for rdata in dmarc_record:
            if 'v=DMARC1' in rdata.strings:
                dmarc_found = True
                break
        if not dmarc_found:
            print(f"{domain} does not have a DMARC record configured. Visit https://easydmarc.com/blog/dmarc-step-by-step-guide/ to learn how to configure DMARC.")
    except dns.resolver.NoAnswer:
        print(f"No TXT record found for _dmarc.{domain}.")
    
    # Check if all records are configured
    if spf_found and dkim_record and dmarc_found:
        print(f"{domain} is secured properly with SPF, DKIM, and DMARC.")
    
# Get input from user
domain = input("Enter a domain to check: ")

# Call the function to check the domain's security
check_domain_security(domain)
