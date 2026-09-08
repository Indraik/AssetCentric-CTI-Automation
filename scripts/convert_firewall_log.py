import csv

# Paths
input_log = "uploads/firewall.log"
output_csv = "logs/firewall_logs.csv"

with open(input_log, "r") as infile, open(output_csv, "w", newline="") as outfile:
    reader = csv.DictReader(infile)
    writer = csv.DictWriter(outfile, fieldnames=["src_ip", "action", "timestamp"])
    writer.writeheader()
    for row in reader:
        writer.writerow({
            "src_ip": row["src_ip"],
            "action": row["action"],
            "timestamp": row["timestamp"]
        })

print(f"Converted {input_log} to {output_csv} with src_ip, action, timestamp.")
