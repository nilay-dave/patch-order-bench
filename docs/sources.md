# Sources

What this project took from outside itself, and what it made up. The distinction
matters more here than in most repositories, because every published figure is a
simulation and a reader has to be able to tell which inputs have provenance.

## The one sourced distributional parameter

**FIRST, EPSS model documentation.** <https://www.first.org/epss/model>

Of 139,473 CVEs with a CVSS 3.x score, 3,735 score at or above an EPSS of 0.1,
which is <!--number:corpus_spec.sourced.share_epss_above_0_1-->0.0268<!--/number-->.
That share is the single anchor the generated EPSS distribution is fitted to. It is
the only distributional parameter in this project that came from a published
measurement rather than from a choice, and `CorpusSpec.describe()` prints it in a
group of its own for that reason.

Everything else about the generated corpus, including the correlation between
severity and exploitation probability that the whole comparison rests on, is a
declared choice. The correlation is swept rather than defended. See
`docs/adr/adr-003-simulation-methodology.md`.

## Definitions the tool has to get right

**EPSS, Exploit Prediction Scoring System.** FIRST.
<https://www.first.org/epss/model>

A probability, between 0 and 1, that a CVE will be exploited in the wild in the
next thirty days. It is a prediction with a time horizon, not a severity measure
and not a statement about impact. Ordering a backlog by EPSS answers "what is most
likely to be attacked soon" and does not answer "what would hurt most if it were".
The tool keeps the two signals in separate fields on `Vulnerability` so that
nothing in the codebase can quietly treat one as the other.

**CVSS v3.1 specification.** FIRST.
<https://www.first.org/cvss/v3.1/specification-document>

Base score and the qualitative severity bands used by `severity_from_cvss`: none
at 0.0, low from 0.1, medium from 4.0, high from 7.0, critical from 9.0. The base
score measures intrinsic severity assuming exploitation, which is why this project
treats it as an impact proxy rather than as a likelihood.

**CISA Known Exploited Vulnerabilities catalogue.** Established by Binding
Operational Directive 22-01.
<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

A list of CVEs with reliable evidence of exploitation in the wild. It is an
observation rather than a prediction, which is why the orderings that put it first
are the ones that win on KEV coverage: the catalogue is the ground truth the metric
is scored against. That is a tautology in the benchmark and a real advantage in
practice, and `docs/limitations.md` says so rather than letting the result stand
unqualified.

**PCI DSS v4.0, requirements 6.3.1 and 6.3.3.** PCI Security Standards Council.
<https://www.pcisecuritystandards.org/document_library/>

6.3.1 is the risk ranking process. 6.3.3 requires that critical or high security
patches, identified by that process, are installed within one month of release, and
that all other applicable security patches are installed "within an appropriate
time frame as determined by the entity", with three months given as an example.

The remediation windows in `pob.models` are 30 days for critical and high, and 90
days for the rest. The 30 is the standard's requirement. The 90 is the standard's
example, adopted here as this project's choice, and a programme that has determined
a different appropriate time frame is not out of compliance with 6.3.3 and is
simply measuring against a different window than this benchmark does. Nothing in
the tool treats 90 days as a mandate.

## Feeds the tool can read and this environment could not reach

`pob fetch` reads the live EPSS and KEV feeds:

- EPSS scores: <https://api.first.org/data/v1/epss>
- KEV catalogue: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>

That code path has tests against recorded responses and has never been run against
the real endpoints, because the network in the environment this was built in
refuses them. It is written, it is typed, it sends a descriptive user agent, and it
is unproven. Anyone with network access can prove or disprove it in one command,
and the README says which command.

## Methods

**Abramowitz and Stegun, Handbook of Mathematical Functions, formula 7.1.26.** The
rational approximation to the error function used by the vectorised normal CDF in
`pob.corpus.generate`. The first version of that code called `math.erf` through
`np.vectorize`, which is a Python loop wearing a NumPy costume.

**Moore and Hodgson, and earliest deadline first scheduling.** The attainability
ceiling in `pob.simulate.metrics` is a greedy earliest deadline first pass over the
findings whose deadlines are still reachable at the given capacity. EDF is optimal
for minimising lateness only on a feasible set, which is why the pass filters to
reachable deadlines first; running it on the open set returned a ceiling of zero
and took two attempts to get right.

**Spearman rank correlation.** Used rather than Pearson wherever severity is
compared against exploitation probability, because the EPSS fit is a monotone
transform of a latent normal and Pearson on the transformed values measures the
transform as much as the relationship.
