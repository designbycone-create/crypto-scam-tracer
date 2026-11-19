"""Look up a scammer: Maigret (usernames) and SpiderFoot (emails, domains, phone numbers, names, IPs).

Both are separate, MIT-licensed programs the user installs; ScamHunter only starts them and reads
their results. Nothing from them is copied into this repository.

Passive only: SpiderFoot runs its "passive" module group, which asks public databases and search
services about the target and never connects to the target's own systems. Maigret checks whether a
username exists on public websites (one profile-page request per site).

Results are leads for an IC3 report, not proof: different people can share a username.
Results stay on this computer in lookups/ (never in updates, on GitHub or in a share copy).
"""
