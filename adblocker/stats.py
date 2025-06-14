import matplotlib.pyplot as plt
from collections import defaultdict

websites = ["facebook", "twitter", "instagram", "google"]

cnt = defaultdict(int)

with open("./blocked_dns_requests.log", "r") as file:
    for line in file:
        line = line.strip()
        space_idx = line.find(" ")
        domain = line[space_idx + 1:]

        matched = False
        for site in websites:
            if site in domain:
                cnt[site] += 1
                matched = True
                break

        if not matched:
            cnt["other"] += 1

x_labels = websites + ["other"]
y_values = [cnt[site] for site in x_labels]

plt.bar(x_labels, y_values, color='blue')
plt.xlabel("Website")
plt.ylabel("Blocked")
plt.title("Blocked URLs by Website")
plt.tight_layout()
plt.savefig("blocked_histogram.png")
