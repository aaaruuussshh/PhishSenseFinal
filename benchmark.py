"""
benchmark.py — Kavach Phishing Detection Benchmark
Evaluates heuristic_engine.analyze_url() on 100 labelled URLs.
Outputs: printed metrics table + benchmark_results.csv
"""

import time
import sys
import os
import pandas as pd

# Allow running from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from heuristic_engine import analyze_url

SCORE_THRESHOLD = 50  # >= 50 → predicted phishing

# ─────────────────────────────────────────────
# TEST DATASET  (50 phishing + 50 safe)
# ─────────────────────────────────────────────

PHISHING_URLS = [
    # SBI variants
    {"url": "https://sbi-kyc-update.online/verify",                     "label": "phishing"},
    {"url": "https://sbi-account-blocked.xyz/unlock",                   "label": "phishing"},
    {"url": "https://sbi.kyc.update.verify.malicious.xyz/otp",          "label": "phishing"},
    {"url": "https://onlinesbi-login.top/secure/login",                  "label": "phishing"},
    {"url": "https://sbimobile-reward.click/claim/upi",                  "label": "phishing"},
    {"url": "https://sbi-urgent-update.pw/kyc",                         "label": "phishing"},
    {"url": "https://sbi-customer-update.live/pan",                     "label": "phishing"},
    {"url": "https://sbionline-kyc.site/aadhaar",                       "label": "phishing"},

    # HDFC variants
    {"url": "https://hdfc-reward-claim.xyz/upi",                        "label": "phishing"},
    {"url": "https://hdfcbank-kyc.online/verify/otp",                   "label": "phishing"},
    {"url": "https://hdfc-account-suspend.top/login",                   "label": "phishing"},
    {"url": "https://hdfcbank-winner.buzz/prize/claim",                 "label": "phishing"},
    {"url": "https://hdfc-upi-update.click/pan",                        "label": "phishing"},

    # ICICI variants
    {"url": "https://icici-kyc-blocked.xyz/unlock",                     "label": "phishing"},
    {"url": "https://icicibank-reward.online/claim",                    "label": "phishing"},
    {"url": "https://icicisecure.top/verify/aadhar",                    "label": "phishing"},
    {"url": "https://icici-upi-suspend.live/update",                    "label": "phishing"},

    # IRCTC variants
    {"url": "https://irctc-refund.top/claim",                           "label": "phishing"},
    {"url": "https://irctc-ticket-reward.xyz/winner",                   "label": "phishing"},
    {"url": "https://irctcrefund-claim.online/otp",                     "label": "phishing"},
    {"url": "https://irctc-cancel-refund.click/verify",                 "label": "phishing"},

    # UIDAI / Aadhaar variants
    {"url": "https://uidai-aadhar-update.click/verify",                 "label": "phishing"},
    {"url": "https://aadhaar-kyc.online/update",                        "label": "phishing"},
    {"url": "https://aadhar-link.xyz/upi/verify",                       "label": "phishing"},
    {"url": "https://uidai-enroll.top/otp/aadhaar",                     "label": "phishing"},

    # Income Tax variants
    {"url": "https://income-tax-refund.buzz/login",                     "label": "phishing"},
    {"url": "https://incometax-return.online/verify",                   "label": "phishing"},
    {"url": "https://income-tax-update.xyz/pan/claim",                  "label": "phishing"},
    {"url": "https://incometaxrefund.top/prize",                        "label": "phishing"},

    # Paytm variants
    {"url": "https://paytm-kyc-update.xyz/verify",                      "label": "phishing"},
    {"url": "https://paytm-reward.online/claim/upi",                    "label": "phishing"},
    {"url": "https://paytm-account-blocked.click/unlock",               "label": "phishing"},

    # PhonePe variants
    {"url": "https://phonepe-offer.xyz/winner/claim",                   "label": "phishing"},
    {"url": "https://phonepe-kyc.online/verify",                        "label": "phishing"},
    {"url": "https://phonepeupi-update.top/otp",                        "label": "phishing"},

    # Electricity / utility bills
    {"url": "https://electricity-ebill.xyz/verify",                     "label": "phishing"},
    {"url": "https://electricity-challan.online/pay",                   "label": "phishing"},
    {"url": "https://ebill-payment.click/upi/pay",                      "label": "phishing"},

    # EPFO / PAN / generic
    {"url": "https://epfo-kyc.online/verify",                           "label": "phishing"},
    {"url": "https://pan-update.xyz/verify/upi",                        "label": "phishing"},
    {"url": "https://rbi-reward.buzz/winner/claim",                     "label": "phishing"},

    # Raw IP phishing
    {"url": "http://192.168.1.100/sbi/kyc",                             "label": "phishing"},
    {"url": "http://103.45.67.89/verify/otp",                           "label": "phishing"},

    # Long suspicious URLs
    {"url": "https://secure-sbi-bank-kyc-update-verify-otp.xyz/user/verify/aadhar/pan/update", "label": "phishing"},
    {"url": "https://hdfc-bank-kyc-aadhar-link-update-urgent.online/user/verify", "label": "phishing"},

    # Axis / PNB
    {"url": "https://axis-kyc-blocked.online/verify",                   "label": "phishing"},
    {"url": "https://pnb-reward.xyz/claim/upi",                         "label": "phishing"},

    # Excessive subdomains
    {"url": "https://sbi.kyc.update.malicious.xyz/login",               "label": "phishing"},
    {"url": "https://verify.kyc.update.secure.irctc-fake.top/otp",      "label": "phishing"},

    # Misc suspicious patterns
    {"url": "https://prize-winner-claim.buzz/upi/reward",               "label": "phishing"},
    {"url": "https://upi-suspend-verify.online/lock/otp",               "label": "phishing"},
]

SAFE_URLS = [
    {"url": "https://www.google.com",               "label": "safe"},
    {"url": "https://www.wikipedia.org",            "label": "safe"},
    {"url": "https://onlinesbi.sbi",                "label": "safe"},
    {"url": "https://www.hdfcbank.com",             "label": "safe"},
    {"url": "https://www.irctc.co.in",              "label": "safe"},
    {"url": "https://www.uidai.gov.in",             "label": "safe"},
    {"url": "https://www.amazon.in",                "label": "safe"},
    {"url": "https://www.flipkart.com",             "label": "safe"},
    {"url": "https://www.zomato.com",               "label": "safe"},
    {"url": "https://www.swiggy.com",               "label": "safe"},
    {"url": "https://www.nykaa.com",                "label": "safe"},
    {"url": "https://www.myntra.com",               "label": "safe"},
    {"url": "https://www.icicibank.com",            "label": "safe"},
    {"url": "https://www.axisbank.com",             "label": "safe"},
    {"url": "https://www.paytm.com",                "label": "safe"},
    {"url": "https://www.phonepe.com",              "label": "safe"},
    {"url": "https://www.rbi.org.in",               "label": "safe"},
    {"url": "https://www.incometax.gov.in",         "label": "safe"},
    {"url": "https://www.epfindia.gov.in",          "label": "safe"},
    {"url": "https://www.passport.gov.in",          "label": "safe"},
    {"url": "https://www.makemytrip.com",           "label": "safe"},
    {"url": "https://www.yatra.com",                "label": "safe"},
    {"url": "https://www.bookmyshow.com",           "label": "safe"},
    {"url": "https://www.redbus.in",                "label": "safe"},
    {"url": "https://www.indiamart.com",            "label": "safe"},
    {"url": "https://www.justdial.com",             "label": "safe"},
    {"url": "https://www.naukri.com",               "label": "safe"},
    {"url": "https://www.linkedin.com",             "label": "safe"},
    {"url": "https://www.github.com",               "label": "safe"},
    {"url": "https://www.stackoverflow.com",        "label": "safe"},
    {"url": "https://www.microsoft.com",            "label": "safe"},
    {"url": "https://www.apple.com",                "label": "safe"},
    {"url": "https://www.python.org",               "label": "safe"},
    {"url": "https://www.numpy.org",                "label": "safe"},
    {"url": "https://www.scipy.org",                "label": "safe"},
    {"url": "https://www.w3schools.com",            "label": "safe"},
    {"url": "https://www.mdn.com",                  "label": "safe"},
    {"url": "https://www.bbc.com",                  "label": "safe"},
    {"url": "https://www.thehindu.com",             "label": "safe"},
    {"url": "https://www.ndtv.com",                 "label": "safe"},
    {"url": "https://www.timesofindia.com",         "label": "safe"},
    {"url": "https://www.hindustantimes.com",       "label": "safe"},
    {"url": "https://www.moneycontrol.com",         "label": "safe"},
    {"url": "https://www.economictimes.com",        "label": "safe"},
    {"url": "https://www.livemint.com",             "label": "safe"},
    {"url": "https://www.sebi.gov.in",              "label": "safe"},
    {"url": "https://www.mca.gov.in",               "label": "safe"},
    {"url": "https://www.npci.org.in",              "label": "safe"},
    {"url": "https://www.kotak.com",                "label": "safe"},
    {"url": "https://www.yesbank.in",               "label": "safe"},
]

TEST_URLS = PHISHING_URLS + SAFE_URLS


# ─────────────────────────────────────────────
# BENCHMARK RUNNER
# ─────────────────────────────────────────────

def run_benchmark():
    records = []
    tp = fp = tn = fn = 0
    total_time = 0.0

    print(f"\nRunning Kavach benchmark on {len(TEST_URLS)} URLs...\n")

    for i, item in enumerate(TEST_URLS, 1):
        url = item["url"]
        true_label = item["label"]

        t0 = time.time()
        try:
            report = analyze_url(url)
            score = report["heuristicScore"]
            flags = report["heuristicFlags"]
        except Exception as exc:
            print(f"  ERROR on {url}: {exc}")
            score = 0
            flags = [f"ERROR: {exc}"]

        elapsed = time.time() - t0
        total_time += elapsed

        predicted_label = "phishing" if score >= SCORE_THRESHOLD else "safe"
        correct = predicted_label == true_label

        if true_label == "phishing" and predicted_label == "phishing":
            tp += 1
            outcome = "TP"
        elif true_label == "safe" and predicted_label == "phishing":
            fp += 1
            outcome = "FP ⚠"
        elif true_label == "safe" and predicted_label == "safe":
            tn += 1
            outcome = "TN"
        else:
            fn += 1
            outcome = "FN ⚠"

        records.append({
            "url": url,
            "true_label": true_label,
            "predicted_label": predicted_label,
            "heuristic_score": score,
            "flags": " | ".join(flags),
            "correct": correct,
            "outcome": outcome,
            "time_s": round(elapsed, 3),
        })

        status = "✓" if correct else "✗"
        print(f"  [{i:3d}] {status} [{outcome}] score={score:3d}  {url[:70]}")

    # ── Metrics ─────────────────────────────────
    total = len(TEST_URLS)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / total if total > 0 else 0.0
    avg_time  = total_time / total if total > 0 else 0.0

    print(f"\n{'='*46}")
    print(f"  KAVACH BENCHMARK RESULTS")
    print(f"{'='*46}")
    print(f"  Total URLs tested:     {total}")
    print(f"  True Positives:        {tp}")
    print(f"  False Positives:       {fp}")
    print(f"  True Negatives:        {tn}")
    print(f"  False Negatives:       {fn}")
    print(f"{'─'*46}")
    print(f"  Precision:             {precision:.4f}")
    print(f"  Recall:                {recall:.4f}")
    print(f"  F1 Score:              {f1:.4f}")
    print(f"  Accuracy:              {accuracy:.4f}")
    print(f"{'─'*46}")
    print(f"  Avg analysis time:     {avg_time:.2f}s per URL")
    print(f"  Total time:            {total_time:.1f}s")
    print(f"{'='*46}\n")

    # ── Save CSV ─────────────────────────────────
    df = pd.DataFrame(records)
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_results.csv")
    df.to_csv(csv_path, index=False)
    print(f"Results saved to: {csv_path}\n")

    # ── False Positive Analysis ──────────────────
    fp_df = df[(df["true_label"] == "safe") & (df["predicted_label"] == "phishing")]
    fn_df = df[(df["true_label"] == "phishing") & (df["predicted_label"] == "safe")]

    if not fp_df.empty:
        print("── TOP FALSE POSITIVES (safe URLs flagged as phishing) ──")
        for _, row in fp_df.iterrows():
            print(f"  score={row['heuristic_score']:3d}  {row['url']}")
            print(f"         flags: {row['flags'][:120]}")
    else:
        print("── No False Positives ✓")

    print()
    if not fn_df.empty:
        print("── TOP FALSE NEGATIVES (phishing URLs missed) ──")
        for _, row in fn_df.iterrows():
            print(f"  score={row['heuristic_score']:3d}  {row['url']}")
            print(f"         flags: {row['flags'][:120]}")
    else:
        print("── No False Negatives ✓")

    print()

    # ── Flag frequency ───────────────────────────
    all_flags = []
    for flags_str in df["flags"]:
        if flags_str:
            all_flags.extend(flags_str.split(" | "))

    flag_counts: dict[str, int] = {}
    for f in all_flags:
        f = f.strip()
        if f:
            flag_counts[f] = flag_counts.get(f, 0) + 1

    print("── MOST COMMON FLAGS ──")
    for flag, count in sorted(flag_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {count:3d}x  {flag}")

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


if __name__ == "__main__":
    run_benchmark()
