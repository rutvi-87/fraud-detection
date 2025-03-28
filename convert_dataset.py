import pandas as pd
import tldextract  # Extract domain names

# Load phishing dataset
df = pd.read_csv("phishing_site_urls.csv")

# Extract domain name only (remove paths)
df["domain"] = df["URL"].apply(lambda url: tldextract.extract(url).registered_domain)

# Convert 'Label' to binary (1 = fraudulent, 0 = safe)
df["is_fraudulent"] = df["Label"].apply(lambda x: 1 if x == "bad" else 0)

# Generate placeholder features (Replace with real values later)
df["domain_age"] = 1  # Default: 1 year (Need WHOIS API for real values)
df["has_ssl"] = df["URL"].apply(lambda url: 1 if url.startswith("https") else 0)
df["whois_privacy"] = 1  # Assume all phishing sites hide WHOIS details
df["spam_score"] = 0.8  # Placeholder spam score

# Keep only necessary columns
df = df[["domain", "domain_age", "has_ssl", "whois_privacy", "spam_score", "is_fraudulent"]]

# Remove duplicates
df = df.drop_duplicates()

# Save as fraud_domains.csv
df.to_csv("fraud_domains.csv", index=False)

print("✅ Dataset converted! You can now train the AI model.")
