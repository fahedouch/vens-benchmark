"""Generate Part-B scenarios: each = a Trivy report (1 CVE) + a vens config.yaml.

Contrastive families (vary ONE context axis, expected direction known) + the two
conference showcases + a wrong-YAML control + a floor. Writes scenarios/<id>/,
scenarios/manifest.json and, beside scenarios/, freeze-scenarios.json, the
corpus's freeze manifest. The `expect` field documents the known-direction
ground truth for analysis.

    python3 make_scenarios.py [--root DIR]

The configs are YAML as PyYAML emits it, so the corpus is reproduced byte for
byte only under the Python and PyYAML versions freeze-scenarios.json records.
"""
import argparse
import hashlib
import json
import math
import os
import platform

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- CVSS ----
# Every report carries one CVSS vector in Trivy's structure, version 3.1 under
# the `nvd` source key: one version and one key across the corpus, so that the
# tier vens reads from a report is never what a contrast varies.
CVSS_VERSION, SOURCE_KEY = "3.1", "nvd"
# A synthetic CVE's vector is ours, chosen to fit its text.
WRITTEN = "written for its text: a synthetic CVE, which no source publishes"
# The showcases' vectors are NVD's own. NVD also gives CVE-2021-44228 a v2
# vector (9.3), left out so that every vector of the corpus is 3.1; like the
# 3.1 one, it floors no axis.
NVD = "NVD CVE API 2.0, fetched 2026-11-18: nvd@nist.gov's Primary cvssMetricV31, record lastModified "

# The CVSS v3.1 base score (FIRST, CVSS v3.1 specification, sections 7.1 and
# 7.4, and Appendix A's Roundup). The prose score and Trivy's V3Score are both
# computed from the vector written, so neither can drift from it.
CVSS31_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
CVSS31_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges required weigh more when the scope changes.
CVSS31_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def cvss31_metrics(vector):
    """The eight base metrics of a CVSS 3.1 vector, in the specification's order; ValueError for any other
    string."""
    prefix, _, rest = vector.partition("/")
    if prefix != "CVSS:3.1":
        raise ValueError(f"{vector!r}: not a CVSS 3.1 vector")
    pairs = [part.partition(":") for part in rest.split("/")]
    names = tuple(name for name, _, _ in pairs)
    if names != CVSS31_METRICS:
        raise ValueError(f"{vector!r}: base metrics {names}, not {CVSS31_METRICS}")
    m = {name: value for name, _, value in pairs}
    allowed = {**CVSS31_WEIGHTS, "PR": CVSS31_PR["U"], "S": {"U": None, "C": None}}
    for name, value in m.items():
        if value not in allowed[name]:
            raise ValueError(f"{vector!r}: {name}:{value} is off the 3.1 scale")
    return m


def cvss31_roundup(x):
    # Appendix A: rounding up on an integer of x * 100000, so that floating-point
    # noise cannot carry a score such as 4.0 up to 4.1.
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss31_score(vector):
    m = cvss31_metrics(vector)
    w = CVSS31_WEIGHTS
    iss = 1 - (1 - w["C"][m["C"]]) * (1 - w["I"][m["I"]]) * (1 - w["A"][m["A"]])
    changed = m["S"] == "C"
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * w["AV"][m["AV"]] * w["AC"][m["AC"]] * CVSS31_PR[m["S"]][m["PR"]] * w["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    return cvss31_roundup(min((1.08 if changed else 1) * (impact + exploitability), 10))


def cvss31_rating(score):
    """The specification's qualitative rating (section 5), as Trivy names it."""
    if score == 0:
        return "NONE"
    return "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


# trivy-db's severities as VendorSeverity holds them, 0 UNKNOWN to 4 CRITICAL.
TRIVY_SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Real CVEs for the two conference showcases (credibility). Official NVD text.
# Contamination is acceptable here: the model recalling the real severity makes
# the de-escalation MORE compelling (it overrides its own "this is critical").
REAL = {
    "log4shell": dict(id="CVE-2021-44228", pkg="org.apache.logging.log4j:log4j-core",
        ver="2.14.1", sev="CRITICAL",
        title="Apache Log4j2 JNDI RCE (Log4Shell)",
        desc="Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, "
             "log messages, and parameters do not protect against attacker controlled LDAP "
             "and other JNDI related endpoints. An attacker who can control log messages or "
             "log message parameters can execute arbitrary code loaded from LDAP servers when "
             "message lookup substitution is enabled. CVSS {score}.",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        source=NVD + "2026-08-11T19:33:44.513"),
    "axios": dict(id="CVE-2023-45857", pkg="axios", ver="1.5.1", sev="MEDIUM",
        title="Axios XSRF-TOKEN disclosure",
        desc="An issue discovered in Axios 1.5.1 inadvertently reveals the confidential "
             "XSRF-TOKEN stored in cookies by including it in the HTTP header X-XSRF-TOKEN "
             "for every request made to any host allowing attackers to view sensitive "
             "information. CVSS {score} (MEDIUM).",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        source=NVD + "2026-06-17T06:29:40.133"),
}

# Reusable synthetic CVEs (fictional IDs -> avoid training-data contamination).
CVES = {
    "rce": dict(id="CVE-2099-0001", pkg="libwidget", ver="1.2.0", sev="CRITICAL",
                title="Remote code execution in libwidget request parser",
                desc="A heap overflow in the HTTP request parser of libwidget allows "
                     "a remote unauthenticated attacker to execute arbitrary code. "
                     "CVSS {score}. Public PoC available.",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source=WRITTEN),
    # Low confidentiality: the attacker gets the fields an error happens to
    # print, not the records of their choosing.
    "infoleak": dict(id="CVE-2099-0002", pkg="jsoncfg", ver="3.4.1", sev="MEDIUM",
                title="Information disclosure in jsoncfg error handler",
                desc="jsoncfg leaks internal object fields in verbose error responses, "
                     "exposing stored records to an authenticated user. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", source=WRITTEN),
    "low": dict(id="CVE-2099-0003", pkg="tinylog", ver="0.9.0", sev="LOW",
                title="Log spoofing via unescaped newline in tinylog",
                desc="tinylog does not escape newlines, letting a local user forge log "
                     "lines. Requires local access, no data impact. CVSS {score}.",
                vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", source=WRITTEN),
    "payment": dict(id="CVE-2099-0004", pkg="paykit", ver="2.0.0", sev="CRITICAL",
                title="Auth bypass in paykit payment gateway",
                desc="paykit fails to validate session tokens, letting a remote attacker "
                     "bypass authentication on the payment API. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", source=WRITTEN),
    "dos": dict(id="CVE-2099-0005", pkg="httpparse", ver="1.1.0", sev="HIGH",
                title="Uncontrolled resource consumption in httpparse",
                desc="A crafted request makes httpparse allocate memory without bound, "
                     "crashing the service (denial of service). No data is disclosed or "
                     "modified; the impact is availability only. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source=WRITTEN),
    # Low integrity: the entries touched are the audit trail's, not the
    # service's data.
    "audit": dict(id="CVE-2099-0006", pkg="auditlog", ver="2.3.0", sev="MEDIUM",
                title="Audit-trail forgery in auditlog",
                desc="An authenticated user can inject or suppress entries in the audit "
                     "trail, breaking accountability and forensic integrity. There is no "
                     "confidentiality or availability impact. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", source=WRITTEN),
    # Local: the attacker must already be able to write a file on the host.
    "locallib": dict(id="CVE-2099-0007", pkg="serdes", ver="4.0.0", sev="HIGH",
                title="Unsafe deserialization in serdes (local input)",
                desc="serdes executes code when it deserializes attacker-influenced input. "
                     "Exploitation requires the attacker to place a crafted file on the host; "
                     "it is not triggerable remotely over HTTP. CVSS {score}.",
                vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", source=WRITTEN),
    # extra DoS-only CVEs (n=3 for the availability discriminator)
    "dos2": dict(id="CVE-2099-0008", pkg="regexval", ver="1.0.0", sev="HIGH",
                title="ReDoS in regexval",
                desc="A catastrophic-backtracking regular expression in regexval lets a "
                     "remote user hang the request thread with crafted input, exhausting CPU "
                     "(denial of service). No data is read or modified. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source=WRITTEN),
    "dos3": dict(id="CVE-2099-0009", pkg="zipread", ver="2.1.0", sev="HIGH",
                title="Decompression bomb in zipread",
                desc="zipread does not bound decompression, so a small crafted archive expands "
                     "to exhaust memory and crash the process (denial of service). The impact "
                     "is availability only. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source=WRITTEN),
    # extra accountability CVEs (n=3 for the accountability discriminator)
    "audit2": dict(id="CVE-2099-0010", pkg="eventbus", ver="1.4.0", sev="MEDIUM",
                title="Security-event suppression in eventbus",
                desc="eventbus lets an authenticated user drop security events before they are "
                     "persisted, so malicious actions go unrecorded. This breaks accountability; "
                     "there is no data disclosure or availability impact. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", source=WRITTEN),
    "audit3": dict(id="CVE-2099-0011", pkg="syslogx", ver="3.0.0", sev="MEDIUM",
                title="Audit-log deletion in syslogx",
                desc="syslogx accepts unauthenticated control messages that delete existing audit "
                     "logs, destroying the forensic trail. This affects the integrity of the audit "
                     "record only. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", source=WRITTEN),
    # extra network RCEs (n=3 for the reachability discriminator)
    "rce2": dict(id="CVE-2099-0012", pkg="pickleio", ver="1.2.0", sev="CRITICAL",
                title="Deserialization RCE in pickleio",
                desc="pickleio deserializes untrusted input received over the network, allowing a "
                     "remote attacker to execute arbitrary code. Public PoC exists. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source=WRITTEN),
    "rce3": dict(id="CVE-2099-0013", pkg="tmplengine", ver="2.5.0", sev="CRITICAL",
                title="Template-injection RCE in tmplengine",
                desc="Server-side template injection in tmplengine lets a remote attacker run "
                     "arbitrary code by submitting a crafted template expression. CVSS {score}.",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source=WRITTEN),
    # ---- NON-TELEGRAPHED variants (construct validity): same mechanism as their
    # telegraphed twins, but title + description no longer name the impact class or
    # assert "no C/I impact" -- the model must INFER the factor, not keyword-match.
    # Each takes its twin's vector, so a twin pair differs in its text alone. ----
    "dos_nt": dict(id="CVE-2099-0020", pkg="bufpool", ver="1.0.0", sev="HIGH",
                title="Resource handling issue in bufpool",
                desc="In bufpool, a request field sets the size of a preallocated buffer with no "
                     "upper bound. A remote request carrying a large value drives memory use up "
                     "until the operating system terminates the worker process. CVSS {score}.",
                twin="dos"),
    "dos_nt2": dict(id="CVE-2099-0021", pkg="xmlflat", ver="2.0.0", sev="HIGH",
                title="Entity expansion in xmlflat",
                desc="xmlflat expands nested entity references in incoming documents. A small "
                     "crafted document expands to many gigabytes in memory and the parser process "
                     "is killed before it returns a response. CVSS {score}.",
                twin="dos2"),
    "audit_nt": dict(id="CVE-2099-0022", pkg="trailkeep", ver="1.3.0", sev="MEDIUM",
                title="Record handling flaw in trailkeep",
                desc="An authenticated user can send a request that alters or removes the server's "
                     "stored record of who performed each administrative action. Current "
                     "application data and service availability are unaffected. CVSS {score}.",
                twin="audit"),
    "audit_nt2": dict(id="CVE-2099-0023", pkg="opstrace", ver="2.2.0", sev="MEDIUM",
                title="Event handling flaw in opstrace",
                desc="opstrace lets an authenticated user discard change-history entries before "
                     "they reach durable storage, so a later review cannot reconstruct what was "
                     "modified. No stored business data is read or changed. CVSS {score}.",
                twin="audit2"),
    "locallib_nt": dict(id="CVE-2099-0024", pkg="cfgloader", ver="1.0.0", sev="HIGH",
                title="Unsafe load in cfgloader",
                desc="cfgloader executes embedded directives when it reads a configuration file "
                     "from the local filesystem during startup. An attacker able to write that "
                     "file on the host runs code as the service account. CVSS {score}.",
                twin="locallib"),
}
CVES = {k: {**c, "vector": CVES[c["twin"]]["vector"], "source": CVES[c["twin"]]["source"]} if "twin" in c else c
        for k, c in CVES.items()}


def trivy_report(cve, vector=True):
    """A Trivy report with the CVE as its one finding. Its severity comes from
    `nvd`, whose rating of the vector it is; a report without a vector keeps
    every other field."""
    score = cvss31_score(cve["vector"])
    if cvss31_rating(score) != cve["sev"]:
        raise ValueError(f"{cve['id']}: {cve['vector']} rates {cvss31_rating(score)}, its severity is {cve['sev']}")
    finding = {
        "VulnerabilityID": cve["id"], "PkgName": cve["pkg"],
        "InstalledVersion": cve["ver"], "Severity": cve["sev"],
        "PkgIdentifier": {"PURL": f"pkg:deb/debian/{cve['pkg']}@{cve['ver']}"},
        "Title": cve["title"], "Description": cve["desc"].format(score=f"{score:.1f}"),
        "PrimaryURL": f"https://example.test/{cve['id']}",
        "SeveritySource": SOURCE_KEY, "VendorSeverity": {SOURCE_KEY: TRIVY_SEVERITY[cve["sev"]]},
    }
    if vector:
        finding["CVSS"] = {SOURCE_KEY: {"V3Vector": cve["vector"], "V3Score": score}}
    return {
        "SchemaVersion": 2, "ArtifactName": "bench/app:latest",
        "ArtifactType": "container_image",
        "Results": [{
            "Target": "app", "Class": "os-pkgs", "Type": "debian",
            "Vulnerabilities": [finding],
        }],
    }


# ---- schema 2 ----
# Every config carries vens's schema-2 marker and declares G2 to G4 at the
# worst case their omission falls back on: every level stays the fallback's,
# while no fallback is counted and a --strict run loads. Every channel not
# logged, so Intrusion detection is not asked and is 9; nothing traced, Loss of
# accountability's `none` column; personal data of millions, Privacy
# violation's cap at 9, so it stays asked wherever the vector leaves
# confidentiality unfloored. Only the accountability family varies one of
# them: traceability per_individual, under which its three answers give three
# levels rather than two.
SCHEMA_VERSION = 2
DETECTION = {"network": "not_logged", "host": "not_logged", "application": "not_logged"}
DATA_SUBJECTS = "millions"
TRACEABILITY = "none"
ACCOUNTABILITY = "per_individual"
# listener (G1) is read from each project's text and is the same within every
# pair a family compares: "svc" names a service, which accepts the connections
# others open (present); a batch tool opens none (absent); a scratch box and a
# context written to mislead state neither (unknown).
LAST = ("controls", "notes")


def cfg(name, desc, listener, traceability=TRACEABILITY, **ctx):
    # The schema-1 fields in the order given, the four new ones, then controls
    # and notes.
    context = {k: v for k, v in ctx.items() if k not in LAST}
    context.update(listener=listener, data_subjects=DATA_SUBJECTS, detection=dict(DETECTION),
                   traceability=traceability)
    context.update({k: ctx[k] for k in LAST if k in ctx})
    return {"schema_version": SCHEMA_VERSION, "project": {"name": name, "description": desc},
            "context": context}


# id -> (cve key, config, expected direction note for analysis)
SCENARIOS = {
    # ---- SHOWCASE 1: CVSS 10.0 RCE that should end LOW (low-value, internal,
    # controlled, unreachable path). ----
    "showcase_high_to_low": (
        "log4shell",
        cfg("internal-batch-tool", "Internal-only batch report generator (Java)", "absent",
            exposure="internal", data_sensitivity="low", business_criticality="low",
            controls={"segmentation": True, "ids": True},
            notes="Log4j is present but message-lookup substitution is disabled "
                  "(log4j2.formatMsgNoLookups=true) and no untrusted/user-controlled input "
                  "is ever passed to the logger. Internal-only tool with no outbound network "
                  "to reach an attacker LDAP server; the RCE path is not reachable."),
        "final risk LOW despite CVSS 10.0 (Log4Shell unreachable + low-value context)"),

    # ---- SHOWCASE 2: CVSS 6.5 info-leak that should rise to HIGH (PII/GDPR,
    # revenue-critical). ----
    "showcase_med_to_high": (
        "axios",
        cfg("customer-portal", "Public customer portal handling PII (React/axios frontend)", "present",
            exposure="internet", data_sensitivity="critical",
            business_criticality="critical", compliance_requirements=["GDPR"],
            notes="axios carries authenticated sessions and customer PII (names, emails, "
                  "national IDs) to first- and third-party APIs. Leaking the XSRF token and "
                  "sensitive headers enables account takeover and a reportable GDPR breach."),
        "final risk HIGH despite CVSS 6.5 (PII + GDPR + internet)"),

    # ---- FAMILY A: exposure axis (same RCE) -> ThreatAgent + final should rise. ----
    "expo_internal": ("rce", cfg("svc", "service", "present", exposure="internal",
                      data_sensitivity="high", business_criticality="high"),
                      "baseline of exposure family"),
    "expo_private": ("rce", cfg("svc", "service", "present", exposure="private",
                     data_sensitivity="high", business_criticality="high"),
                     "ThreatAgent/final >= internal"),
    "expo_internet": ("rce", cfg("svc", "service", "present", exposure="internet",
                      data_sensitivity="high", business_criticality="high"),
                      "ThreatAgent/final >= private"),

    # ---- FAMILY B: controls axis (same RCE, internet) -> Vulnerability should drop. ----
    "ctrl_off": ("rce", cfg("svc", "service", "present", exposure="internet",
                 data_sensitivity="high", business_criticality="high"),
                 "baseline, no controls"),
    "ctrl_on": ("rce", cfg("svc", "service", "present", exposure="internet",
                data_sensitivity="high", business_criticality="high",
                controls={"waf": True, "ids": True, "segmentation": True},
                notes="WAF blocks the malicious request pattern; IDS detects exploit."),
                "Vulnerability/final <= ctrl_off"),

    # ---- WRONG-YAML: a genuinely critical internet payment auth-bypass, but the
    # context LIES (says internal + low criticality). Honest section: follow or flag? ----
    "wrong_yaml": ("payment", cfg("mislabeled", "context contradicts reality", "unknown",
                   exposure="internal", data_sensitivity="low",
                   business_criticality="low",
                   notes="Nothing sensitive here, just a test box."),
                   "reveals blind-follow vs flag; not a pass/fail direction"),

    # ---- FLOOR: low-severity CVE in a low context -> should score low. ----
    "floor": ("low", cfg("dev-box", "developer scratch box", "unknown", exposure="internal",
              data_sensitivity="low", business_criticality="low"),
              "final risk LOW"),

    # ---- FAMILY: data_sensitivity ladder (info-leak = a real C/I breach). ----
    "sens_low": ("infoleak", cfg("svc", "service", "present", exposure="internet",
                 data_sensitivity="low", business_criticality="high"),
                 "technical_impact + final: low end of sensitivity ladder"),
    "sens_high": ("infoleak", cfg("svc", "service", "present", exposure="internet",
                  data_sensitivity="high", business_criticality="high"),
                  "technical_impact/final >= sens_low"),
    "sens_critical": ("infoleak", cfg("svc", "service", "present", exposure="internet",
                      data_sensitivity="critical", business_criticality="high"),
                      "technical_impact/final >= sens_high"),

    # ---- FAMILY: business_criticality (RCE, fixed elsewhere). ----
    "crit_low": ("rce", cfg("svc", "service", "present", exposure="internet",
                 data_sensitivity="high", business_criticality="low"),
                 "business_impact + final: low end"),
    "crit_critical": ("rce", cfg("svc", "service", "present", exposure="internet",
                      data_sensitivity="high", business_criticality="critical"),
                      "business_impact/final >= crit_low"),

    # ---- FAMILY: compliance on/off (info-leak). ----
    "comp_none": ("infoleak", cfg("svc", "service", "present", exposure="internet",
                  data_sensitivity="high", business_criticality="high"),
                  "business_impact baseline"),
    "comp_gdpr": ("infoleak", cfg("svc", "service", "present", exposure="internet",
                  data_sensitivity="high", business_criticality="high",
                  compliance_requirements=["GDPR"]),
                  "business_impact/final >= comp_none"),

    # ---- DISCRIMINATOR (availability_requirement): pure DoS + critical data.
    # Naive rule sets technical=data_sensitivity(9); reading the CVE shows no C/I
    # breach, so technical should track availability_requirement instead. ----
    "disc_dos": ("dos", cfg("svc", "streaming service", "present", exposure="internet",
                 data_sensitivity="critical", business_criticality="high",
                 availability_requirement="high"),
                 "DoS-only: a model should not max technical via data_sensitivity"),

    # ---- DISCRIMINATOR (accountability): accountability CVE + low data.
    # Naive rule sets technical=data_sensitivity(low) and misses accountability.
    # The family crosses the answer with what is traced, per_individual here.
    # Its five configs keep their schema-1 audit key, which moves nothing in
    # schema 2 and which the before reads as it always did. ----
    "disc_audit": ("audit", cfg("svc", "financial ledger", "present", ACCOUNTABILITY, exposure="internet",
                   data_sensitivity="low", business_criticality="high",
                   audit_requirement="high"),
                   "accountability CVE, traceability per_individual: Loss of accountability's answer "
                   "should read defeats_attribution, not follow the low data"),

    # ---- DISCRIMINATOR (irrelevant control): local deserialization + WAF on.
    # A WAF cannot block a local-file exploit; a model should NOT drop vulnerability
    # for it (contrast with ctrl_on, where the WAF blocks a web RCE). The WAF alone
    # is set, so the pair with disc_ctrl_off_local differs in it alone. ----
    "disc_ctrl_irrelevant": ("locallib", cfg("svc", "service", "present", exposure="internet",
                             data_sensitivity="high", business_criticality="high",
                             controls={"waf": True}),
                             "WAF is irrelevant to a local-file exploit: vulnerability should not drop"),

    # ---- DISCRIMINATOR (reachability via notes): same RCE + high context; only the
    # operator's notes differ. The rule ignores notes -> identical; a model should move. ----
    "reach_yes": ("rce", cfg("svc", "service", "present", exposure="internet",
                  data_sensitivity="critical", business_criticality="critical",
                  notes="The vulnerable endpoint is internet-exposed and we have observed "
                        "exploitation attempts in our logs; the code path is reachable."),
                  "reachable: final HIGH"),
    "reach_no": ("rce", cfg("svc", "service", "present", exposure="internet",
                 data_sensitivity="critical", business_criticality="critical",
                 notes="The vulnerable code path is compiled out / feature-flagged off in "
                       "this build; it is not reachable at runtime."),
                 "unreachable: final < reach_yes"),

    # ---- Generalize each discriminator to n=3 (3 distinct CVEs) so a finding is a
    # pattern, not a single-CVE anecdote. ----
    "disc_dos2": ("dos2", cfg("svc", "api service", "present", exposure="internet",
                  data_sensitivity="critical", business_criticality="high",
                  availability_requirement="high"),
                  "DoS-only: technical should not max via data_sensitivity"),
    "disc_dos3": ("dos3", cfg("svc", "api service", "present", exposure="internet",
                  data_sensitivity="critical", business_criticality="high",
                  availability_requirement="high"),
                  "DoS-only: technical should not max via data_sensitivity"),
    "disc_audit2": ("audit2", cfg("svc", "ledger service", "present", ACCOUNTABILITY, exposure="internet",
                    data_sensitivity="low", business_criticality="high",
                    audit_requirement="high"),
                    "accountability, traceability per_individual: Loss of accountability's answer "
                    "should read defeats_attribution"),
    "disc_audit3": ("audit3", cfg("svc", "ledger service", "present", ACCOUNTABILITY, exposure="internet",
                    data_sensitivity="low", business_criticality="high",
                    audit_requirement="high"),
                    "accountability, traceability per_individual: Loss of accountability's answer "
                    "should read defeats_attribution"),
    "reach2_yes": ("rce2", cfg("svc", "service", "present", exposure="internet",
                   data_sensitivity="critical", business_criticality="critical",
                   notes="The deserialization endpoint is reachable and we see exploitation "
                         "attempts in our logs."),
                   "reachable: final HIGH"),
    "reach2_no": ("rce2", cfg("svc", "service", "present", exposure="internet",
                  data_sensitivity="critical", business_criticality="critical",
                  notes="The deserialization call site is unreachable: the feature is disabled "
                        "and no untrusted input reaches it."),
                  "unreachable: final < reach2_yes"),
    "reach3_yes": ("rce3", cfg("svc", "service", "present", exposure="internet",
                   data_sensitivity="critical", business_criticality="critical",
                   notes="User-supplied templates are rendered on this path; it is reachable."),
                   "reachable: final HIGH"),
    "reach3_no": ("rce3", cfg("svc", "service", "present", exposure="internet",
                  data_sensitivity="critical", business_criticality="critical",
                  notes="Templates are never user-supplied in this build; the injection path "
                        "is not reachable."),
                  "unreachable: final < reach3_yes"),

    # ---- Fix the irrelevant-control test: same local bug WITHOUT the WAF, to isolate
    # whether the WAF wrongly lowered vulnerability in disc_ctrl_irrelevant. ----
    "disc_ctrl_off_local": ("locallib", cfg("svc", "service", "present", exposure="internet",
                            data_sensitivity="high", business_criticality="high"),
                            "local bug, no controls: vulnerability baseline for the WAF test"),

    # ---- NON-TELEGRAPHED discriminators: identical context to the telegraphed disc_*
    # twin; only the CVE text changes (impact class no longer named). Pairing measures
    # whether a right answer came from reasoning or from keyword-matching the CVE. ----
    "disc_dos_nt": ("dos_nt", cfg("svc", "streaming service", "present", exposure="internet",
                    data_sensitivity="critical", business_criticality="high",
                    availability_requirement="high"),
                    "non-telegraphed DoS: technical should not max via data_sensitivity"),
    "disc_dos_nt2": ("dos_nt2", cfg("svc", "api service", "present", exposure="internet",
                     data_sensitivity="critical", business_criticality="high",
                     availability_requirement="high"),
                     "non-telegraphed DoS: technical should not max via data_sensitivity"),
    "disc_audit_nt": ("audit_nt", cfg("svc", "financial ledger", "present", ACCOUNTABILITY, exposure="internet",
                      data_sensitivity="low", business_criticality="high",
                      audit_requirement="high"),
                      "non-telegraphed accountability, traceability per_individual: Loss of "
                      "accountability's answer should read defeats_attribution"),
    "disc_audit_nt2": ("audit_nt2", cfg("svc", "ledger service", "present", ACCOUNTABILITY, exposure="internet",
                       data_sensitivity="low", business_criticality="high",
                       audit_requirement="high"),
                       "non-telegraphed accountability, traceability per_individual: Loss of "
                       "accountability's answer should read defeats_attribution"),
    "disc_ctrl_irrelevant_nt": ("locallib_nt", cfg("svc", "service", "present", exposure="internet",
                                data_sensitivity="high", business_criticality="high",
                                controls={"waf": True}),
                                "non-telegraphed local bug: WAF irrelevant, vulnerability should not drop"),
    # The non-telegraphed local bug without the WAF: disc_ctrl_irrelevant_nt's twin.
    "disc_ctrl_off_local_nt": ("locallib_nt", cfg("svc", "service", "present", exposure="internet",
                               data_sensitivity="high", business_criticality="high"),
                               "non-telegraphed local bug, no controls: vulnerability baseline for the WAF test"),
}

# The DoS and accountability scenarios and their twins once more, their reports
# without the CVSS vector: vens then asks every impact question, so the model's
# reading of confidentiality and integrity in their texts stays visible where
# the vector's floors otherwise set it. Diagnostics: no verdict reads them.
WITHOUT_VECTOR = ("disc_dos", "disc_dos2", "disc_dos3", "disc_dos_nt", "disc_dos_nt2",
                  "disc_audit", "disc_audit2", "disc_audit3", "disc_audit_nt", "disc_audit_nt2")
COPY_SUFFIX = "_novec"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def corpus():
    """{scenario id: (cve, config, expect, the scenario it copies or None)}: the scenarios with a vector, then the
    copies without one."""
    allcves = {**CVES, **REAL}
    out = {sid: (allcves[k], c, e, None) for sid, (k, c, e) in SCENARIOS.items()}
    for sid in WITHOUT_VECTOR:
        cve, config, _, _ = out[sid]
        out[sid + COPY_SUFFIX] = (cve, config, f"copy of {sid} without a CVSS vector: a diagnostic, no verdict", sid)
    return out


def vector_entry(cve):
    entry = {"vector": cve["vector"], "version": CVSS_VERSION, "source_key": SOURCE_KEY, "source": cve["source"],
             "score": cvss31_score(cve["vector"])}
    if "twin" in cve:
        entry["vector_of"] = CVES[cve["twin"]]["id"]
    return entry


def files():
    """{path relative to the root: bytes}: every scenario file, then the freeze manifest, which holds the others'
    sha256."""
    out, manifest, vectors, listener, per_individual = {}, {}, {}, {}, []
    scenarios = corpus()
    for sid, (cve, config, expect, copy_of) in scenarios.items():
        d = f"scenarios/{sid}"
        out[f"{d}/report.json"] = json.dumps(trivy_report(cve, vector=copy_of is None), indent=2).encode()
        out[f"{d}/config.yaml"] = yaml.safe_dump(config, sort_keys=False).encode()
        manifest[sid] = {"cve": cve["id"], "sev": cve["sev"], "expect": expect}
        if copy_of:
            manifest[sid]["copy_of"] = copy_of
        vectors[sid] = None if copy_of else vector_entry(cve)
        listener[sid] = config["context"]["listener"]
        if config["context"]["traceability"] == ACCOUNTABILITY:
            per_individual.append(sid)
    out["scenarios/manifest.json"] = json.dumps(manifest, indent=2).encode()
    with_vector = sum(1 for v in vectors.values() if v)
    freeze = {
        "generator": {name: sha256(open(os.path.join(HERE, name), "rb").read())
                      for name in ("make_scenarios.py", "requirements.txt")},
        "python": platform.python_version(),
        "pyyaml": yaml.__version__,
        "schema_version": SCHEMA_VERSION,
        "declared": {"detection": DETECTION, "data_subjects": DATA_SUBJECTS,
                     "traceability": {"default": TRACEABILITY, ACCOUNTABILITY: per_individual},
                     "listener": listener},
        "counts": {"configs": len(vectors), "with_vector": with_vector, "without_vector": len(vectors) - with_vector,
                   "setting_ids": sorted(s for s, (_, c, _, _) in scenarios.items()
                                         if c["context"].get("controls", {}).get("ids"))},
        "vectors": vectors,
        "files": {p: sha256(b) for p, b in sorted(out.items())},
    }
    out["freeze-scenarios.json"] = (json.dumps(freeze, indent=2) + "\n").encode()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=HERE, help="where scenarios/ and freeze-scenarios.json go (default: here)")
    a = ap.parse_args(argv)
    written = files()
    for rel, data in written.items():
        path = os.path.join(a.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    manifest = json.loads(written["scenarios/manifest.json"])
    print(f"wrote {len(manifest)} scenarios to {os.path.join(a.root, 'scenarios')}")
    for sid, m in manifest.items():
        print(f"  {sid:24s} {m['sev']:8s} {m['expect']}")


if __name__ == "__main__":
    main()
