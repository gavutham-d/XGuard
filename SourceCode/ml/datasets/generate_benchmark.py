"""
Dataset Generator and Curator for XGuard ML Pipeline.
Generates a structured, reproducible benchmark dataset of benign and malicious URLs
specifically stratified into:
- Train Split
- Validation Split
- In-Distribution Test Split
- Unseen-Domain Test Split (to test zero-day / unseen domain generalization)
"""

import json
import os
import random
from typing import List, Dict

# Set random seed for reproducibility
random.seed(42)

BENIGN_SAMPLES = [
    # Top tech & services
    {"url": "https://www.google.com/search?q=cybersecurity+best+practices", "category": "benign"},
    {"url": "https://mail.google.com/mail/u/0/#inbox", "category": "benign"},
    {"url": "https://docs.google.com/document/d/1aB2cD3e/edit", "category": "benign"},
    {"url": "https://www.microsoft.com/en-us/windows", "category": "benign"},
    {"url": "https://azure.microsoft.com/en-us/products/virtual-machines", "category": "benign"},
    {"url": "https://www.apple.com/iphone-16-pro/specs/", "category": "benign"},
    {"url": "https://developer.apple.com/documentation/swiftui", "category": "benign"},
    {"url": "https://www.amazon.com/dp/B08N5WRWNW", "category": "benign"},
    {"url": "https://aws.amazon.com/s3/pricing/", "category": "benign"},
    {"url": "https://www.paypal.com/us/home", "category": "benign"},
    {"url": "https://www.paypal.com/signin", "category": "benign"},
    {"url": "https://www.netflix.com/browse", "category": "benign"},
    {"url": "https://help.netflix.com/en/node/412", "category": "benign"},
    {"url": "https://www.chase.com/personal/checking", "category": "benign"},
    {"url": "https://secure.chase.com/web/auth/#/logon/logon/chaseonline", "category": "benign"},
    {"url": "https://www.bankofamerica.com/smallbusiness/", "category": "benign"},
    {"url": "https://www.wellsfargo.com/help/", "category": "benign"},
    {"url": "https://github.com/torvalds/linux", "category": "benign"},
    {"url": "https://github.com/fastapi/fastapi/releases", "category": "benign"},
    {"url": "https://gitlab.com/gitlab-org/gitlab/-/issues", "category": "benign"},
    {"url": "https://bitbucket.org/product", "category": "benign"},
    {"url": "https://stackoverflow.com/questions/50711900/fastapi-async-routes", "category": "benign"},
    {"url": "https://en.wikipedia.org/wiki/Transport_Layer_Security", "category": "benign"},
    {"url": "https://en.wikipedia.org/wiki/Phishing", "category": "benign"},
    {"url": "https://www.nytimes.com/section/technology", "category": "benign"},
    {"url": "https://www.bbc.com/news/technology", "category": "benign"},
    {"url": "https://edition.cnn.com/business", "category": "benign"},
    {"url": "https://www.reuters.com/technology/", "category": "benign"},
    {"url": "https://news.ycombinator.com/item?id=3849102", "category": "benign"},
    {"url": "https://www.reddit.com/r/netsec/", "category": "benign"},
    {"url": "https://www.reddit.com/r/MachineLearning/", "category": "benign"},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API", "category": "benign"},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS", "category": "benign"},
    {"url": "https://pypi.org/project/scikit-learn/", "category": "benign"},
    {"url": "https://huggingface.co/models", "category": "benign"},
    {"url": "https://www.cloudflare.com/learning/security/what-is-zero-trust/", "category": "benign"},
    {"url": "https://www.cisa.gov/resources-tools/resources/phishing-guidance", "category": "benign"},
    {"url": "https://owasp.org/www-project-top-ten/", "category": "benign"},
    {"url": "https://www.mitre.org/news-insights/insights-icon", "category": "benign"},
    {"url": "https://attack.mitre.org/techniques/T1566/", "category": "benign"},
    {"url": "https://arxiv.org/abs/2301.00001", "category": "benign"},
    {"url": "https://www.nature.com/articles/d41586-023-01000-0", "category": "benign"},
    {"url": "https://www.science.org/journal/science", "category": "benign"},
    {"url": "https://web.mit.edu/research/", "category": "benign"},
    {"url": "https://cs.stanford.edu/people/faculty", "category": "benign"},
    {"url": "https://www.ox.ac.uk/admissions/graduate", "category": "benign"},
    {"url": "https://www.cam.ac.uk/research", "category": "benign"},
    {"url": "https://www.harvard.edu/programs/", "category": "benign"},
    {"url": "https://berkeley.edu/academics", "category": "benign"},
    {"url": "https://www.nationalgeographic.com/environment", "category": "benign"},
    {"url": "https://www.theverge.com/tech", "category": "benign"},
    {"url": "https://arstechnica.com/information-technology/", "category": "benign"},
    {"url": "https://wired.com/category/security/", "category": "benign"},
    {"url": "https://bleepingcomputer.com/news/security/", "category": "benign"},
    {"url": "https://krebsonsecurity.com/about/", "category": "benign"},
    {"url": "https://www.spotify.com/us/premium/", "category": "benign"},
    {"url": "https://www.linkedin.com/feed/", "category": "benign"},
    {"url": "https://www.airbnb.com/rooms/1029384", "category": "benign"},
    {"url": "https://www.booking.com/city/gb/london.html", "category": "benign"},
    {"url": "https://weather.com/weather/today/l/USNY0996:1:US", "category": "benign"},
    {"url": "https://duckduckgo.com/?q=ai+threatguard", "category": "benign"},
    {"url": "https://www.twitch.tv/directory", "category": "benign"},
    {"url": "https://discord.com/channels/@me", "category": "benign"},
    {"url": "https://slack.com/help/articles/2026-getting-started", "category": "benign"},
    {"url": "https://zoom.us/pricing", "category": "benign"},
    {"url": "https://www.dropbox.com/plans", "category": "benign"},
    {"url": "https://drive.google.com/drive/my-drive", "category": "benign"},
    {"url": "https://medium.com/topic/cybersecurity", "category": "benign"},
    {"url": "https://www.coursera.org/learn/cyber-security-specialization", "category": "benign"},
    {"url": "https://www.edx.org/school/harvardx", "category": "benign"},
    {"url": "https://www.khanacademy.org/computing/computer-science", "category": "benign"}
]

# Systematic variation generator for benign URLs to create robust sample size
BENIGN_EXTENSIONS = [
    "blog/post-102", "about-us", "contact", "support/faq", "pricing/enterprise",
    "docs/v2/getting-started", "api/reference", "legal/privacy-policy", "terms-of-service",
    "careers/openings", "products/overview", "community/forum", "press/releases/2026",
    "security/disclosure", "status/uptime", "downloads/client-mac", "guide/installation"
]
BENIGN_DOMAINS = [
    "shopify.com", "stripe.com", "adobe.com", "atlassian.com", "salesforce.com",
    "oracle.com", "ibm.com", "intel.com", "amd.com", "nvidia.com",
    "cisco.com", "zoom.us", "hubspot.com", "canva.com", "figma.com",
    "notion.so", "linear.app", "docker.com", "kubernetes.io", "python.org",
    "golang.org", "rust-lang.org", "nodejs.org", "mozilla.org", "apache.org",
    "debian.org", "ubuntu.com", "redhat.com", "canonical.com", "ietf.org"
]

MALICIOUS_SAMPLES = [
    # Subdomain brand spoofing
    {"url": "http://paypal.com.account-verification-service.net/login.php?cmd=verify", "category": "phishing"},
    {"url": "https://paypal-security-update.account-protection.xyz/signin/index.html", "category": "phishing"},
    {"url": "http://appleid.apple.com.manage-verify.org/auth/security_check.php", "category": "phishing"},
    {"url": "https://microsoft-online-365.session-recovery-auth.top/login.srf?id=92", "category": "phishing"},
    {"url": "http://accounts.google.com.sign-in-portal-recovery.info/ServiceLogin", "category": "phishing"},
    {"url": "http://chase-online-banking.secure-logon-alerts.biz/auth/verify.aspx", "category": "phishing"},
    {"url": "https://wellsfargo.customer-support-session.club/login/portal", "category": "phishing"},
    {"url": "http://netflix-billing-alert.update-payment-info.cc/your-account", "category": "phishing"},
    {"url": "https://amazon-prime-delivery.claim-refund-voucher.icu/order-status", "category": "phishing"},
    {"url": "http://binance-security.verify-kyc-wallet.vip/en/login", "category": "phishing"},
    {"url": "https://coinbase-pro.asset-recovery-center.wang/signin/step2", "category": "phishing"},
    {"url": "http://steampowered.community-trade-gift.click/profiles/76561198", "category": "phishing"},
    {"url": "https://bankofamerica.online-id-verification.shop/sign-in.do", "category": "phishing"},
    {"url": "http://dropbox-shared-document.view-invoice.work/download.php?doc=91", "category": "phishing"},
    {"url": "https://adobe-document-cloud.sign-contracts.live/review/doc.pdf.exe", "category": "malware"},

    # Typosquatting
    {"url": "http://www.paypa1.com/cgi-bin/webscr?cmd=_login-run", "category": "typosquatting"},
    {"url": "http://goog1e.com/support/account/recover", "category": "typosquatting"},
    {"url": "https://micros0ft.com/en-us/security/renew-license", "category": "typosquatting"},
    {"url": "http://amaz0n-prime.com/account/billing/fix-card", "category": "typosquatting"},
    {"url": "https://netf1ix-verify.com/login?next=stream", "category": "typosquatting"},
    {"url": "http://chasee-bank.com/secure/login/auth", "category": "typosquatting"},
    {"url": "https://wel1sfargo.com/identity/security-questions", "category": "typosquatting"},
    {"url": "http://app1e-id-support.com/find-my-iphone/locked", "category": "typosquatting"},
    {"url": "https://twittter-verify.com/oauth/authorize?token=bad", "category": "typosquatting"},
    {"url": "http://faceb00k-security-notice.com/checkpoint/login", "category": "typosquatting"},
    {"url": "https://linked1n-jobs.com/network/messages/view", "category": "typosquatting"},
    {"url": "http://instagrann-verify-badge.com/accounts/confirm", "category": "typosquatting"},

    # IP address hosts
    {"url": "http://185.220.101.5/paypal/signin.php?session=active", "category": "ip_host"},
    {"url": "http://194.26.29.112:8080/secure/bankofamerica/login.htm", "category": "ip_host"},
    {"url": "http://45.145.185.9/download/invoice_scan_october.exe", "category": "malware"},
    {"url": "http://91.240.118.23:8888/admin/login.php", "category": "ip_host"},
    {"url": "http://178.128.240.91/portal/chase/verify-ssn.php", "category": "ip_host"},
    {"url": "http://198.54.117.200/netflix/billing/update.html", "category": "ip_host"},
    {"url": "http://103.151.125.10/apple/login.php?id=99", "category": "ip_host"},

    # Homograph / Punycode
    {"url": "http://xn--gogle-pqa.com/service-login/challenge", "category": "phishing"}, # googӏe
    {"url": "https://xn--appl-4qa.com/my-icloud/find-device", "category": "phishing"},
    {"url": "http://xn--pypal-4ve.com/signin/webscr", "category": "phishing"},
    {"url": "https://xn--mcrosoft-e1a.com/office365/auth", "category": "phishing"},

    # Direct malware downloads and executable drops
    {"url": "http://system-speedup-utility.download-hub.cc/driver_update.scr", "category": "malware"},
    {"url": "http://bank-statement-archive.file-storage-direct.top/statement_q3.pdf.exe", "category": "malware"},
    {"url": "https://free-crypto-miner-bot.github-mirror.biz/crypto_booster.bat", "category": "malware"},
    {"url": "http://zoom-meeting-installer.media-share.party/Zoom_Update_Patch.vbs", "category": "malware"},
    {"url": "http://steam-wallet-hack-tool.free-games.xyz/wallet_generator.exe", "category": "malware"},
    {"url": "https://urgent-security-patch.it-helpdesk-urgent.link/patch-KB91823.msi", "category": "malware"},
    {"url": "http://whatsapp-gold-edition.mobile-updates.site/whatsapp_gold.apk", "category": "malware"},

    # Credential stuffing / parameter packed / excessive symbols
    {"url": "http://secure-login-gateway.com/auth?redirect=https%3A%2F%2Fpaypal.com&token=secret@@login_user", "category": "phishing"},
    {"url": "http://online-account-recovery-centre.info/step1/verify.php?user=admin&cmd=reset_password&urgent=true", "category": "phishing"},
    {"url": "http://banking-auth-portal-secure-service-center.tk/online-banking/us/login.html", "category": "phishing"},
    {"url": "https://suspicious-crypto-giveaway-elon.xyz/claim-free-eth-airdrop.html", "category": "scam"},
    {"url": "http://irs-tax-refund-claim-portal.gov-refunds.online/file-tax/ssn-verify.php", "category": "scam"}
]

# Systematic malicious variation generator
MALICIOUS_DOMAINS = [
    "account-update-notice.com", "secure-banking-verification.net", "identity-protection-check.info",
    "customer-support-session.org", "wallet-security-recovery.biz", "billing-portal-direct.club",
    "login-security-gateway.top", "urgent-notice-action.xyz", "appleid-resolve-locked.cc",
    "paypal-resolution-center.vip", "amazon-delivery-hold.link", "netflix-card-declined.site"
]
MALICIOUS_PATHS = [
    "signin/index.php", "auth/verify-identity.html", "login/checkpoint.aspx", "recover/reset-password",
    "webscr/cmd-login", "billing/update-credit-card", "security/unlock-account.php", "kyc/upload-id-document"
]


def build_full_dataset() -> List[Dict]:
    """Compile dataset with controlled balance, categories, and split assignment."""
    data = []
    
    # Add curated benign
    for item in BENIGN_SAMPLES:
        data.append({
            "url": item["url"],
            "label": 0,
            "category": "benign"
        })
        
    # Generate variations of benign
    for domain in BENIGN_DOMAINS:
        for ext in BENIGN_EXTENSIONS:
            scheme = "https://" if random.random() > 0.1 else "http://"
            sub = random.choice(["", "www.", "api.", "docs.", "support."])
            query = random.choice(["", "?lang=en", "?ref=footer", "?utm_source=docs", "?page=1&size=20"])
            url = f"{scheme}{sub}{domain}/{ext}{query}"
            data.append({
                "url": url,
                "label": 0,
                "category": "benign"
            })

    # Add curated malicious
    for item in MALICIOUS_SAMPLES:
        data.append({
            "url": item["url"],
            "label": 1,
            "category": item["category"]
        })

    # Generate synthetic malicious variations
    for domain in MALICIOUS_DOMAINS:
        for path in MALICIOUS_PATHS:
            scheme = "http://" if random.random() > 0.3 else "https://"
            sub = random.choice(["login.", "secure.", "verify.", "account.", "portal.", "signin."])
            brand_token = random.choice(["paypal", "apple", "chase", "microsoft", "google", "netflix", "wellsfargo"])
            
            # Combine deceptive subdomains and paths
            rand_type = random.random()
            if rand_type < 0.4:
                url = f"{scheme}{brand_token}.{domain}/{path}?id={random.randint(1000, 9999)}"
                cat = "phishing"
            elif rand_type < 0.7:
                url = f"{scheme}{sub}{domain}/{brand_token}/{path}?urgent=1"
                cat = "phishing"
            else:
                ext = random.choice([".exe", ".scr", ".bat", ".vbs"])
                url = f"{scheme}{sub}{domain}/downloads/{brand_token}_security_update{ext}"
                cat = "malware"
                
            data.append({
                "url": url,
                "label": 1,
                "category": cat
            })

    # Deduplicate URLs
    seen = set()
    unique_data = []
    for row in data:
        normalized = row["url"].strip().lower()
        if normalized not in seen:
            seen.add(normalized)
            unique_data.append(row)

    # Assign Splits:
    # 70% Train, 15% Validation, 15% Test
    # Additionally, partition a subset of unique domains strictly to "test_unseen_domain"
    # to evaluate zero-day domain detection capability without domain leakage.
    random.shuffle(unique_data)
    
    # Identify domains
    unseen_benign_domains = {"debian.org", "canonical.com", "ietf.org"}
    unseen_malicious_domains = {"appleid-resolve-locked.cc", "netflix-card-declined.site"}
    
    labeled_dataset = []
    for row in unique_data:
        url = row["url"]
        is_unseen = any(d in url for d in unseen_benign_domains | unseen_malicious_domains)
        if is_unseen:
            split = "test_unseen_domain"
        else:
            r = random.random()
            if r < 0.70:
                split = "train"
            elif r < 0.85:
                split = "val"
            else:
                split = "test"
        row["split"] = split
        labeled_dataset.append(row)

    return labeled_dataset


if __name__ == "__main__":
    dataset = build_full_dataset()
    os.makedirs(os.path.dirname(__file__), exist_ok=True)
    out_path = os.path.join(os.path.dirname(__file__), "url_dataset.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    total = len(dataset)
    benign_count = sum(1 for d in dataset if d["label"] == 0)
    malicious_count = sum(1 for d in dataset if d["label"] == 1)
    splits = {}
    for d in dataset:
        splits[d["split"]] = splits.get(d["split"], 0) + 1

    print(f"Dataset generated successfully at: {out_path}")
    print(f"Total samples: {total}")
    print(f"Benign: {benign_count} ({benign_count/total*100:.1f}%)")
    print(f"Malicious: {malicious_count} ({malicious_count/total*100:.1f}%)")
    print(f"Splits distribution: {splits}")
