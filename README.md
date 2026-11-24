# vens-benchmark

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21775841.svg)](https://doi.org/10.5281/zenodo.21775841)

Which LLM should you run [vens](https://github.com/venslabs/vens) with? This benchmarks models on the job vens actually does: scoring a CVE's risk from a scanner report plus project context.

**Paper:** [Which LLM Should Score Your CVEs?](paper/vens-benchmark.pdf): methodology, all 12 models, and where it fails. Its numbers come from the [`paper-v1`](https://github.com/venslabs/vens-benchmark/tree/paper-v1) tag.

The benchmark has two halves. Half A, CVE understanding, is unchanged since the paper. Half B, context use, stays as published at `paper-v1`, and `main` rebuilds it as the measuring chain of [venslabs/vens#310](https://github.com/venslabs/vens/issues/310).

## Which model to pick

200 CVEs, CTIBench CVSS task, July 2026. MAD = mean absolute error vs the NVD base score (lower is better).

| Model | MAD | $/200 | Note |
|---|---|---|---|
| claude-sonnet-4-6 | 0.75 | $1.88 | most accurate, stable; default for signed VEX |
| gpt-5.5 | 0.75 | $4.12 | same accuracy as sonnet, 2× the price; skip |
| gpt-5.4-mini | 0.84 | $0.48 | best value; jittery, run n≥3 |
| gemini-2.5-pro | 0.88 | $1.16 | solid middle |
| gemini-2.5-flash-lite | 1.15 | $0.07 | cheapest; over-rates and adds little on context |
| claude-haiku-4-5 | 1.29 | $0.52 | below the value line |

A constant "always 7.5" guess scores 1.57. A model above that isn't worth the call.

**Short version:** sonnet if you sign or audit the output, gpt-5.4-mini for cheap-and-good, flash-lite for throwaway triage. Don't pay for gpt-5.5.

## Half A: CVE understanding

A model predicts the CVSS v3.1 vector from the CVE text (the public CTIBench CTI-VSP task), scored by MAD against NVD: raw CVE understanding. Its code, `cti_runner.py`, `cti_metric.py` and `cti_analyze.py`, is the same on `main` as at `paper-v1`. Its page and its cost against accuracy chart stay in [`report.html` at `paper-v1`](https://github.com/venslabs/vens-benchmark/blob/paper-v1/report.html), beside the published Half B. The page is one self-contained file: save it with `git show paper-v1:report.html > ../report.html` and open it in a browser.

```
git clone https://github.com/venslabs/vens-benchmark && cd vens-benchmark
pip install -r requirements.txt
export OPENAI_API_KEY=...          # and/or ANTHROPIC_API_KEY, GOOGLE_API_KEY

python3 cti_runner.py --models <name> --limit 200    # accuracy (MAD vs NVD); CTIBench's data first, see below
python3 cti_analyze.py                                # ranking, Pareto front, failure catalog
```

Add a model in one line in the `MODELS` dict (`cti_runner.py`). Local models run through [Ollama](https://ollama.com) with no key and no cost, e.g. `--models qwen2.5:7b`.

## Half B as published, at `paper-v1`

The paper's Half B ran 35 project-context scenarios through `vens generate`, with `--llm-temperature 0` and `--llm-seed 7` and three repeats per cell, and checked that the OWASP risk moves the right way when you change exposure, data sensitivity, criticality, reachability, or controls. Every model was measured against a non-LLM rule engine it has to beat, `baseline.py`.

`report.html` at `paper-v1` presents its results: context sensitivity, the two showcases (Log4Shell rated LOW and an axios leak rated HIGH) and where models fail. The paper's Half B numbers come from that tag, which keeps that Half B's code and its 35 scenarios: the old `make_scenarios.py`, `ctx_runner.py` and `ctx_analyze.py`, and `stats_extra.py` for the paper's extra statistics. `main` rewrote the first three, regenerated the scenarios, and removed `stats_extra.py` and `report.html`. That Half B ran on an unreleased `+dirty` vens build that no ref names, so its figures cannot be rebuilt from a named ref, at `paper-v1` or elsewhere.

## Half B as rebuilt: the measuring chain

On `main`, Half B measures what vens publishes, the VEX and each CVE's OWASP rating, at two vens commits: the before, on vens's `main`, and the after, on its `310-step3` branch, which reworks the scoring for venslabs/vens#310. It reads every attempt, failed ones included. CI tests each part on vens's mock LLM and a fake `gh`: no model is called and no key is needed.

- **Frozen corpus.** `make_scenarios.py` writes 46 scenarios under `scenarios/`, each a one-CVE Trivy report and a vens config in schema 2. 36 carry a CVSS 3.1 vector; the other 10 copy a scenario without its vector, as a diagnostic. `freeze-scenarios.json` freezes the corpus: every file's sha256, the sha256 of `make_scenarios.py` and `requirements.txt`, the Python and PyYAML versions, and each vector with its source. The runner refuses any other corpus, and the tests fail when the generator's output drifts. To change the corpus, re-freeze it deliberately: edit the generator, run `python3 make_scenarios.py` under the recorded Python and PyYAML, commit the corpus with its new freeze, and set `FROZEN` in `chain/campaign.py` to the new freeze's sha256.
- **Scenario runner.** `ctx_runner.py` runs each scenario, model and replicate through the before's binary, then the after's. Each run is `vens generate` at batch 1 with `--attest`, a debug folder per attempt and each provider's default sampling. A failed attempt is retried, up to `--retry-cap` attempts in all, and an attempt still running at `--timeout` seconds is killed. Every attempt is recorded with vens's log, its exit status and its times. The campaign folder is the archive, sealed with `SHA256SUMS`; `ctx_runner.py` documents the order, the retries and the record.
- **Demo scan.** vens-demo's [`baseline.yml`](https://github.com/venslabs/vens-demo/blob/main/.github/workflows/baseline.yml) scores an archived scan of 74 CVEs in three contexts, with vens built at the commit it is given. Each attempt uploads its VEX, its attempt record (`attempt.json`), vens's log and the model calls. `python3 -m chain.dispatch` starts a campaign's workflow runs, each one replicate of one arm, replicate r of the before beside replicate r of the after. It reruns failed jobs and appends every dispatch, rerun and late run to `dispatch-log.jsonl`. That log maps each run id and run attempt to its arm, model and campaign replicate. A campaign is archived once `check-late` passes. `chain/dispatch.py` documents the commands and the log.
- **Reader.** `python3 -m chain.read` reads a scenario campaign, or `baseline.yml`'s downloads through `--dispatch-log`, and prints one JSON object per attempt: how it ended and why, its ratings, its calls and recovery calls, and an estimate of its cost. The downloads are laid out as `chain/downloads.py` says: one folder per workflow run, its artefacts beside the run's `run.json`, `jobs.json` and `artifacts.json` from the GitHub API.
- **Reachability.** The reader also takes the after at `310-step3b` 19b333a to 5f797bf, which ask one more question of every CVE, first: reachability (R). Its answer is kept per CVE in each record beside the 16 factors, which the check against the VEX reads unchanged. Answered `not_reachable`, a CVE is not asked Opportunity, Ease of exploit or the four technical impacts, and their levels come from source `reachability`; from 0421679 a flagged one keeps an adjustment call on confidentiality alone, its request as at 5f797bf, which can lower Privacy violation. The reader checks that rule in `answers.json`, and counts R with the other questions in answer agreement and cannot_tell. `chain/contract.py` gives the rules under R with `reach=`, its answer; `chain/verdicts.py` keeps b7c0435's, for historical runs: it refuses a run that asks R, and the families mark each row read on one as not certified.
- **C1 + C2.** The reader also takes the after at `310-c1c2`, venslabs/vens#310's candidate, without the reachability relay (plan Z0d: the commit N, 33a5dbf, `N_COMMIT` in `chain/contract.py`). No R: a CVE gets at most nine questions, and Loss of confidentiality, integrity and availability come from source `cvss`, the worst value of the CVE's usable CVSS v3 vectors through C2's table, 9 each and `cvss_v3_missing` without one; Privacy violation keeps its floor where those vectors give C:N. vens publishes no VEX status. `chain/contract.py` mirrors the rules (`c1c2_` functions). The after's contract is pinned, never read off the runs: `ctx_analyze.py --rules c1c2` (or `--commit after=` a commit `CONTRACTS` names); the reader refuses an `answers.json` off the pinned contract, and any `declared` block or VEX status under any contract. Under C1 + C2 every after cell, a scenario or a demo context of one model, is an implementation item recomputed from its frozen inputs (`chain/conform.py`), binding on every expected replicate: no status, no declared block, and the levels, vector, severity and score its own answers give. `ctx_analyze.py` exits 1 when one fails or is inconclusive. The families read `CHECKS_C1C2`: `showcase_med_to_high`'s high or critical stays carried under read5's eligibility rule, `showcase_high_to_low`'s low and the reach pairs' gaps are diagnostics, the notes alone, and #333's expected low and step 1's reachability contract are printed as withdrawn, not met. `python3 -m chain.contract --demo SCAN --scenarios DIR` prints what C2 reads of each, and the analysis report opens on it.
- **C1 + C2'.** The candidate since C2''s one-shot screen, and S2's after: `310-c1c2` at the C2' commit, N plus C2' (`C2P_COMMIT` in `chain/contract.py`, its one pin). C1 + C2 but Loss of availability, read from the CVE's worst CVSS v3 `A` in the column `availability_requirement` gives, OWASP's secondary then primary services: N 1/1, L 1/5, H 5/7, 9 without a usable v3 vector. Low and medium are secondary, high and critical primary; unset reads primary and the CVE, one with a usable v3 vector, counts `availability_requirement_missing`. `ctx_analyze.py --rules c1c2p`, or `--commit after=` the C2' commit, pins it: the same checks and gate as C1 + C2, every after cell recomputed with that column and both C2 counters. An `answers.json` counting the field missing, or with Loss of availability in the secondary column, shows C1 + C2' and is refused under `c1c2`; C1 + C2's record is one C1 + C2' also writes where the field is high or critical, so the reader takes it under `c1c2p`, and the gate tells the two apart on the run's config. Under either contract no unrated entry counts `cvss_v3_missing` or `availability_requirement_missing` and each counter's total is its entries' sum; a reading pinned to a contract the run's own commit does not pin refuses the run. The marker commit (`MARKER_COMMIT`, e3007ed, on the C2' commit; 7ce0211, the first, read the same), S2's after, also pins `c1c2p`, and S2 reads it with `--commit after=` that commit: its runs carry one `vens:impact-provenance` property per VEX vulnerability, `missing-cvss-v3-fallback` where the report gives no usable v3 vector and the CVE counts `cvss_v3_missing`, `cvss-v3` otherwise; any other commit's runs carry none.
- **c1c2b.** The rating-policy fix: `310-policy` at the policy commit (`POLICY_COMMIT` in `chain/contract.py`, 301c00e, on the marker commit). C1 + C2''s levels and marker, Skill level from source `worst_case`, and the severity and score read on one impact instead of max(T, B): the business impact when the config declares `data_subjects` (any band, `none` included), the technical impact otherwise. Each VEX vulnerability carries one `vens:impact-basis`, `business` or `technical`. `ctx_analyze.py --rules c1c2b`, or `--commit after=` the policy commit, pins it: every after cell recomputed on its published basis, the basis required equal to the config's; any other commit's runs carry none. Target (ii) and the null model's after read the same impact. `tests/test_c1c2b.py` checks it, against the policy commit's mock with `VB_VENS_POLICY`.
- **c1c2r.** The repair: `310-policy` at the repair commit (`REPAIR_COMMIT` in `chain/contract.py`, ed1ed1c, over the policy commit). c1c2b's rules, but Financial damage and Reputation damage are no longer asked: Go sets each from the config's `business_criticality` at t, OWASP's band of max(LC, LI, LAV) (high without a usable v3 vector), on the decided table (`DAMAGE`: FD low 1/1/1, medium 1/1/3, high 1/3/7, critical 3/7/9; RD low 1/1/1, medium 1/1/4, high 1/4/5, critical 4/5/9), source `criticality`. The VEX metadata carries one `vens:rating-policy`, `2`. `ctx_analyze.py --rules c1c2r`, or `--commit after=` the repair commit, pins it: every after cell recomputed, Financial and Reputation damage from the table, the rating on the published basis, the rating policy required. Under c1c2b and c1c2r a rating without one valid basis is refused whatever the run's commit. `tests/test_c1c2r.py` checks it, against the repair commit's mock with `VB_VENS_REPAIR`.
- **Java check.** The OWASP reference calculator (`us.springett:owasp-risk-rating-calculator` 1.0.1 from Maven Central, its sha256 checked) parses and scores every rating. `python3 -m chain.javarun` runs it on vens's mock over the after's VEX: the scenarios, the demo scan's three contexts and vens's two quickstart reports. With `--before`, it checks the before's VEX on the scenarios and the demo scan too. It feeds each failure path an input of its own, and exits 1 on any exit status or verdict other than the expected one.
- **Analysis.** `python3 ctx_analyze.py` reads the same inputs through the same reader and writes one Markdown report. It covers the legal-vector and recomputable-score targets, the demo scan's spread, entropy, cross-model spread and band agreement, the scenario families, a table against the null model `baseline.py` beside the after's fallback, attempts and recovery calls, cost, and the KPI measures. Measured cost and estimates never share a table. The fallback is a mock campaign run with `VENS_MOCK_LLM_CANNOT_TELL=cannot_tell`, passed with `--fallback`. `--demo`, `--usage`, `--draw-list` and `--jar` add the other optional inputs, which `ctx_analyze.py` documents.
- **One key per arm.** Each arm calls the model on its own key, so the provider's usage export shows each arm's spend apart. The keys are `OPENAI_API_KEY_BEFORE` and `OPENAI_API_KEY_AFTER`, or `ANTHROPIC_API_KEY_BEFORE` and `ANTHROPIC_API_KEY_AFTER`: in the runner's environment, and as vens-demo's secrets, where `baseline.yml`'s `arm` input picks one. With `--key-suffix SCENARIOS`, the runner reads `OPENAI_API_KEY_BEFORE_SCENARIOS` and so on, so a scenario campaign's spend shows on keys of its own. For a real model, a missing key, or one key for both arms, stops the runner before any call.
- **What it does not measure.** Campaigns run at batch 1, one CVE per call, so batch interaction is not measured. The scenarios hold one CVE each, so within-project spread, ranking entropy and cross-model spread come from the demo scan alone. Both corpora are Trivy reports. The cost per attempt is an estimate; the measured spend is a campaign's, and an arm's only with a key per arm. Agreement with a family's expected direction is consistency, not correctness. The report's last section lists the rest.

### On vens's mock

Build both arms from [venslabs/vens](https://github.com/venslabs/vens), then run the chain on vens's mock LLM, which needs no key and costs nothing. Keep the binaries and the outputs outside this checkout: an untracked file in it makes every record name the vens-benchmark commit `+dirty`.

```
BEFORE=<a commit on vens main>; AFTER=<a commit on vens 310-step3>   # full commits, e.g. the two chain.yml pins
git clone https://github.com/venslabs/vens ../vens
git -C ../vens checkout -q $BEFORE && (cd ../vens && go build -o ../bin/vens-before ./cmd/vens)
git -C ../vens checkout -q $AFTER && (cd ../vens && go build -o ../bin/vens-after ./cmd/vens)

python3 ctx_runner.py --campaign mock1 --out ../measurements/mock1 \
    --before ../bin/vens-before --before-commit $BEFORE --after ../bin/vens-after --after-commit $AFTER \
    --model mock/mock --replicates 1 --retry-cap 2 --timeout 300 --parallel 4
python3 -m chain.read ../measurements/mock1                         # one JSON object per attempt
python3 ctx_analyze.py ../measurements/mock1 --out ../measurements/mock1.md

python3 -m chain.javacheck fetch-jar ../jar
git clone https://github.com/venslabs/vens-demo ../vens-demo
git -C ../vens-demo checkout -q 7ab1570f8068b16b965571f363726bc051d06d9f  # the commit CI pins
python3 -m chain.javarun --vens ../bin/vens-after --commit $AFTER --before ../bin/vens-before --before-commit $BEFORE \
    --scenarios scenarios --demo ../vens-demo --quickstart ../vens/examples/quickstart \
    --jar ../jar/owasp-risk-rating-calculator-1.0.1.jar --out ../javarun
```

The Java run needs a JDK: `--jdk DIR`, else `$JAVA_HOME/bin`, else the folder of `javac` on `PATH`. For a real model, give its dated id, e.g. `--model openai/gpt-5.4-mini-2026-03-17` (`claude-sonnet-4-6` has none: add `--undated claude-sonnet-4-6`), export its provider's two keys, and set the campaign's replicates, retry cap, timeout and parallelism, e.g. `--replicates 10 --retry-cap 4 --timeout 600 --parallel 4`.

## Tests and CI

```
python3 -m unittest
```

With nothing set, the tests that need an optional input skip and name the variable to set. CI ([`chain.yml`](.github/workflows/chain.yml)) runs on every pull request and every push to `main`: it builds vens at the two commits it pins, fetches vens-demo, its `baseline.yml` and the calculator's JAR, sets the variables of the first five rows below, and runs `python3 -m unittest -v`. Its JDK comes from `JAVA_HOME`. The variables take absolute paths.

| Variable | What it names |
|---|---|
| `VB_VENS_AFTER`, `VB_VENS_BEFORE` | vens binaries built at the after and the before commits CI pins |
| `VB_DEMO` | a vens-demo checkout at the commit CI pins |
| `VB_QUICKSTART` | vens's `examples/quickstart` at the after commit |
| `VB_JAR` | the calculator's JAR, from `python3 -m chain.javacheck fetch-jar DIR` |
| `VB_BASELINE` | vens-demo's `baseline.yml` with the attempt record, at the commit CI pins; required when `CI=true` |
| `VB_JDK` | a JDK's `bin` folder, else `$JAVA_HOME/bin`, else the folder of `javac` on `PATH` |
| `VB_VENS_REACH` | a vens binary built at `310-step3b` 5f797bf, whose reachability question `tests/test_reach.py` runs on the mock |
| `VB_VENS_MARKER` | a vens binary built at `310-c1c2`'s marker commit, S2's after, which `tests/test_c1c2_mock.py` runs on the mock |
| `VB_VENS_C1C2P`, `VB_VENS_C1C2` | vens binaries built at `310-c1c2`'s C2' commit and at N, which `tests/test_c1c2_mock.py` runs beside the marker commit |
| `VB_VENS_MARKER_SRC` | vens's source tree at the marker commit, whose Go tests freeze the demo scan's C2 counts |
| `VB_0B_MEASUREMENTS`, `VB_0B_READ0B` | the archives of venslabs/vens#310's step 0B and its reader |
| `VB_R2` | two real-model `baseline.yml` runs, one per arm, with their dispatch log |
| `VB_0A_DRAWS` | the CVE ids that earlier draws used |

The last three rows name inputs kept outside this repository.

## Data & license

- Code and the vens context scenarios: Apache-2.0.
- **CTIBench data is CC BY-NC-SA 4.0 (NonCommercial) and is not shipped here.** Fetch it at runtime (it derives from NVD, public domain):

  ```
  mkdir -p data && gh api repos/xashru/cti-bench/contents/data/cti-vsp.tsv \
    -H "Accept: application/vnd.github.raw" > data/cti-vsp.tsv
  ```

  Attribution: CTIBench, https://github.com/xashru/cti-bench (NeurIPS 2024).

API keys are read from the environment, never committed.
