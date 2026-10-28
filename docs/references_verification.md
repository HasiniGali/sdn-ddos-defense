# Reference verification

Checked 2026-10-28. Bibliographic metadata comes from the Crossref REST API (`https://api.crossref.org/works/<doi>`), with OpenAlex and Semantic Scholar used to cross-check it. ScienceDirect article pages returned HTTP 403 to automated fetches, so none of the Elsevier abstracts below were read on the publisher site. Each abstract summary names the source it came from. Where only fragments of an abstract were available (search-engine snippets of the ScienceDirect abstract or highlights, or an institutional repository page), the summary says so. Numbers appear only when they were in the abstract text actually retrieved.

"Online" dates are the first-online dates OpenAlex records. "Issue" dates are the Crossref `published-print` values. IEEE style uses the issue year.

## Summary table (Task A)

| # | Short title | Status | Discrepancies (given vs. found) |
|---|---|---|---|
| 1 | Explainable FCIL for encrypted TC | CONFIRMED | None |
| 2 | FedXAI | CONFIRMED | Cosmetic only. Crossref prints the title as "Explainable AI(FedXAI)" with no space before the parenthesis; given is "AI (FedXAI)". The TalTech/NAU repository records use the spaced form. |
| 3 | Choir-IDS | CONFIRMED | None. Online July 2025, issue January 2026, so year 2026 is correct. |
| 4 | Collaborative DDoS defense, SDN-based AIoT | CONFIRMED | None. Online December 2024, issue May 2025, so year 2025 is correct. |
| 5 | FMARL (Tellache et al.) | CONFIRMED | None. Issue July 2026. |
| 6 | SDN DDoS survey (Wang et al.) | CONFIRMED | None. Issue May 2026. |
| 7 | CO-DEFEND | CONFIRMED | None. The "et al." stands for 7 more authors (8 in total, listed below). Issue February 2026. |
| 8 | CANDICE | CONFIRMED (authors supplied) | Authors were missing from the citation as given. Found: S. Li, R. Du, J. Chen, K. He, C. Wu, Y. Feng. |
| 9 | When the weakest model sees the threat | CONFIRMED (authors completed) | Given "C. Minh et al."; the full list has 5 authors (below). |
| 10 | eX-NIDS | CONFIRMED WITH DISCREPANCIES | (a) Authors were missing; found: P. R. B. Houssel, S. Layeghy, P. Singh, M. Portmann. (b) "Part B" is **UNCONFIRMED**: Crossref has no issue or part field for this article, and the publisher page was unreachable (403). (c) The journal's registered title is "Computers and Electrical Engineering"; given is "Computers & Electrical Engineering". IEEE abbreviation: *Comput. Electr. Eng.* |

Volume, article number, year and DOI matched Crossref exactly for all 10 references.

---

## Task A: per-reference detail

### [A1] Carillo et al. (2025)

**Verified IEEE citation:**
R. Carillo, F. Cerasuolo, G. Bovenzi, D. Ciuonzo, and A. Pescapè, "Explainable federated class incremental learning for encrypted network traffic classification," *Comput. Netw.*, vol. 269, Art. no. 111448, Sep. 2025, doi: 10.1016/j.comnet.2025.111448.

- Sources: https://api.crossref.org/works/10.1016/j.comnet.2025.111448 ; https://api.openalex.org/works/https://doi.org/10.1016/j.comnet.2025.111448 ; DOI resolves to PII S1389128625004153 (https://www.sciencedirect.com/science/article/pii/S1389128625004153)
- Full author names (Crossref): Raffaele Carillo, Francesco Cerasuolo, Giampaolo Bovenzi, Domenico Ciuonzo, Antonio Pescapè.
- Online 2025-06-19; issue September 2025.
- Discrepancies: none.

**Abstract summary** (full abstract via OpenAlex):
- *Problem:* Traffic classifiers built with ML/DL have trouble keeping up with new or updated apps and services. Their decisions are not interpretable. Traffic also varies by geographic region, which calls for decentralized, privacy-preserving collaborative updates.
- *Method:* A Federated Class Incremental Learning (FCIL) framework that combines class-incremental learning with federated learning, plus an XAI methodology using sample-based and attribution-based explanations. It also analyses a per-client bias-correction layer.
- *Datasets:* two public encrypted-traffic datasets. Only CESNET-TLS22 is named in the abstract.
- *Results (authors' claims):* In small networks, fewer synchronisations help retain old knowledge. Frequent updates help assimilate new classes. BiC+ is best with 2 clients and iCaRL+ is best with 10 clients, reaching **82% and 79% F1 on CESNET-TLS22** respectively.
- *Relevance:* Federated and explainable, but not SDN and not DDoS (the task is encrypted traffic classification). Cite it as related work on federated XAI for network traffic and on incremental learning when new classes appear.

### [A2] Kalakoti, Nõmm, Bahsi (2025)

**Verified IEEE citation:**
R. Kalakoti, S. Nõmm, and H. Bahsi, "Federated learning of explainable AI (FedXAI) for deep learning-based intrusion detection in IoT networks," *Comput. Netw.*, vol. 270, Art. no. 111479, Oct. 2025, doi: 10.1016/j.comnet.2025.111479.

- Sources: https://api.crossref.org/works/10.1016/j.comnet.2025.111479 ; https://experts.nau.edu/en/publications/federated-learning-of-explainable-aifedxai-for-deep-learning-base/ ; PII S1389128625004463
- Full author names: Rajesh Kalakoti, Sven Nõmm, Hayretdin Bahsi.
- Online 2025-06-25; issue October 2025.
- Discrepancies: only the title spacing noted in the table. Volume, article number, year and DOI match.

**Abstract summary** (paraphrased from the NAU research-portal record of the abstract; Crossref, OpenAlex and Semantic Scholar have no abstract):
- *Problem:* IoT devices are exposed to botnets. Federated learning protects privacy, but deep models are black boxes.
- *Method:* The FedXAI framework. An LSTM is trained with horizontal FL and FedAvg for binary and multiclass detection (botnet type and attack type). Client-side SHAP explanations are securely aggregated so the server can approximate global-model explanations without seeing client data. SHAP is compared against LIME and Integrated Gradients.
- *Datasets:* not named in the abstract text retrieved.
- *Results (authors' claims):* Detection performance is high (no numbers in the retrieved text). Aggregated client-side explanations "closely approximate the global model explanations". SHAP scored best on faithfulness, complexity, monotonicity and robustness.
- *Relevance:* The closest methodological match to a SHAP-based project. It is federated and explainable with SHAP, but it targets IoT botnet and intrusion detection, not SDN. It supports the choice of SHAP over LIME and IG.

### [A3] Sahoo, Kar, Abdelmoniem, Chatzopoulos (2026)

**Verified IEEE citation:**
J. P. Sahoo, B. Kar, A. M. Abdelmoniem, and D. Chatzopoulos, "Choir-IDS: A federated learning framework for fidelity-calibrated explainable intrusion detection system for edge-IoT networks," *Inf. Fusion*, vol. 125, Art. no. 103473, Jan. 2026, doi: 10.1016/j.inffus.2025.103473.

- Sources: https://api.crossref.org/works/10.1016/j.inffus.2025.103473 ; https://researchportal.hkust.edu.hk/en/publications/choir-ids-a-federated-learning-framework-for-fidelity-calibrated-/ ; https://dl.acm.org/doi/10.1016/j.inffus.2025.103473 ; PII S1566253525005469
- Full author names: Jyoti Prakash Sahoo, Binayak Kar, Ahmed M. Abdelmoniem, Dimitris Chatzopoulos.
- Online 2025-07-05; issue January 2026.
- Discrepancies: none.

**Abstract summary** (from the HKUST research-portal abstract):
- *Problem:* ML-based IDSs for IoT can only be trusted if their outputs are faithful (fidelity) and explainable. FL helps with privacy and scale, and ensembles may help with performance.
- *Method:* Choir-IDS, "Neural Boosting Ensembles" (deep learning combined with ensemble learning) built through federated learning. It uses isotonic and sigmoid probability calibration, and explains decisions with LIME and SHAP.
- *Datasets:* not named in the abstract.
- *Results:* the abstract gives no numbers.
- *Relevance:* Federated, explainable with SHAP, and calibrated, for edge-IoT intrusion detection. Not SDN-specific and not DDoS-specific. Useful when arguing for probability calibration alongside SHAP explanations.

### [A4] Ma, Su (2025)

**Verified IEEE citation:**
J. Ma and W. Su, "Collaborative DDoS defense for SDN-based AIoT with autoencoder-enhanced federated learning," *Inf. Fusion*, vol. 117, Art. no. 102820, May 2025, doi: 10.1016/j.inffus.2024.102820.

- Sources: https://api.crossref.org/works/10.1016/j.inffus.2024.102820 ; https://www.sciencedirect.com/science/article/abs/pii/S1566253524005980 (seen only via search snippet; direct fetch 403) ; https://www.researchgate.net/publication/386439948 (search snippet)
- Full author names: Jie Ma, Wei Su.
- Online 2024-12-04; issue May 2025.
- Discrepancies: none.

**Abstract summary** (from search-engine snippets of the ScienceDirect abstract and highlights; full abstract **not retrieved**):
- *Problem:* DDoS defense in software-defined AIoT (SD-AIoT), with privacy of network feature data, and a high false-alarm rate when few labelled outliers are available.
- *Method:* An outlier-aware, semi-supervised Autoencoder-MLP detector trained with federated learning. Secure multiparty computation protects feature privacy and provides trusted aggregation of local updates. For mitigation, a visual console pushes back attack paths using distributed rate-limiting on P4 switches.
- *Datasets:* the snippet reports evaluation on CICIDS2017 and InSDN. This should be checked against the full text.
- *Results (authors' claims, per the highlights):* "effective attack detection, fast recovery, and minimal performance impact", with improvements over state-of-the-art SDN-based defenses. No verified numbers.
- *Relevance:* The most directly related of the 10. It is SDN, DDoS-specific and federated, and covers both detection and mitigation (rate-limiting). It is not SHAP-explainable. It works as a contrast for a single-controller, SHAP-explained design.

### [A5] Tellache, Amara Korba, Mokhtari, Ghamri-Doudane (2026)

**Verified IEEE citation:**
A. Tellache, A. Amara Korba, A. Mokhtari, and Y. Ghamri-Doudane, "Collaborative privacy-preserving network intrusion detection: A federated multi-agent reinforcement learning approach," *Comput. Commun.*, vol. 256, Art. no. 108565, Jul. 2026, doi: 10.1016/j.comcom.2026.108565.

- Sources: https://api.crossref.org/works/10.1016/j.comcom.2026.108565 ; https://api.openalex.org/works/https://doi.org/10.1016/j.comcom.2026.108565 ; PII S0140366426001556
- Full author names: Amine Tellache, Abdelaziz Amara Korba, Amdjed Mokhtari, Yacine Ghamri-Doudane.
- Online 2026-05-20; issue July 2026.
- Discrepancies: none. The given "A. A. Korba" stands for the family name "Amara Korba" (Crossref family = "Amara Korba"), so IEEE form is "A. Amara Korba". This is a formatting note; the person is the same.

**Abstract summary** (full abstract via OpenAlex):
- *Problem:* ML-based IDSs need full retraining when new attacks appear, need large datasets that privacy makes hard to share, and face non-IID attack distributions across organisations.
- *Method:* Federated Multi-Agent RL (FMARL). In the first level, N RL agents, one per attack type, are each trained federatedly with class-level FedAvg. A second-level decision agent aggregates their outputs. The agents use an enhanced DQN with cost-sensitive learning and a weighted MSE loss.
- *Dataset:* CIC-IDS-2017.
- *Results (authors' claims):* **99% accuracy** across most configurations, a **minimum of 97%** under extreme non-IID conditions, and a "notably low" false positive rate.
- *Relevance:* Federated and privacy-preserving NIDS. Not explainable, not SDN, not DDoS-specific. Related work for collaborative and federated detection.

### [A6] Wang, Liu, Meng, Chen (2026)

**Verified IEEE citation:**
W. Wang, Y. Liu, Q. Meng, and Z. Chen, "DDoS attack detection and defense techniques in software defined networks: A survey," *Comput. Sci. Rev.*, vol. 60, Art. no. 100921, May 2026, doi: 10.1016/j.cosrev.2026.100921.

- Sources: https://api.crossref.org/works/10.1016/j.cosrev.2026.100921 ; https://www.sciencedirect.com/science/article/abs/pii/S1574013726000304 (search snippet only)
- Full author names: Wei Wang, Yong Liu, Qian Meng, Zihang Chen.
- Online 2026-01-31; issue May 2026. Semantic Scholar has no record of this DOI.
- Discrepancies: none.

**Abstract summary** (from search-engine snippets of the ScienceDirect abstract; full abstract **not retrieved**):
- *Problem:* Separating the control plane from the data plane in SDN creates DDoS exposure: attackers can exhaust controller resources or saturate the control channel.
- *Method:* A systematic review covering an attack taxonomy, an assessment of architectural weaknesses, an evaluation of detection methods, the limitations of current countermeasures, and future directions.
- *Datasets and results:* not applicable (survey); none stated.
- *Relevance:* A survey that is SDN-specific and DDoS-specific. It fits the background and related-work chapter, including the threat model on controller saturation and flow-table exhaustion.

### [A7] Cajaraville-Aboy et al. (2026)

**Verified IEEE citation:**
D. Cajaraville-Aboy, M. Moure-Garrido, C. Beis-Penedo, C. Garcia-Rubio, R. P. Díaz-Redondo, C. Campo, A. Fernández-Vilas, and M. Fernández-Veiga, "CO-DEFEND: Continuous decentralized federated learning for secure DoH-based threat detection," *Comput. Netw.*, vol. 276, Art. no. 111961, Feb. 2026, doi: 10.1016/j.comnet.2025.111961.

(Shortened IEEE form, allowed for 7 or more authors: D. Cajaraville-Aboy *et al.*)

- Sources: https://api.crossref.org/works/10.1016/j.comnet.2025.111961 ; https://api.semanticscholar.org/graph/v1/paper/DOI:10.1016/j.comnet.2025.111961 ; PII S1389128625009260
- Full author names: Diego Cajaraville-Aboy, Marta Moure-Garrido, Carlos Beis-Penedo, Carlos Garcia-Rubio, Rebeca P. Díaz-Redondo, Celeste Campo, Ana Fernández-Vilas, Manuel Fernández-Veiga.
- Online 2025-12-21; issue February 2026.
- Discrepancies: none.

**Abstract summary** (full abstract via Semantic Scholar):
- *Problem:* Attackers use DNS-over-HTTPS (DoH) tunnelling to hide malicious activity in encrypted DNS. Training detectors needs large datasets that organisations cannot share for privacy reasons.
- *Method:* CO-DEFEND, a decentralized FL (DFL) framework with online training on real-time batches of DoH flows. It adapts SVM, logistic regression, decision trees and random forests for federated use. DT and RF use model *selection* instead of aggregation, so each participant keeps interpretable local trees.
- *Dataset:* CIRA-CIC-DoHBrw-2020.
- *Results (authors' claims):* effective detection of malicious DoH tunnels with better scalability and computational efficiency than more complex alternatives such as neural networks. No numbers in the abstract.
- *Relevance:* Federated (decentralized), with tree models (RF) that are interpretable by design. Not SDN and not DDoS (the threat is DoH tunnelling). It shows how RF can be handled in FL, which is relevant if the project's RF/XGBoost detector were ever federated.

### [A8] Li et al. (2026), CANDICE

**Verified IEEE citation:**
S. Li, R. Du, J. Chen, K. He, C. Wu, and Y. Feng, "CANDICE: An explainable and intelligent framework for network intrusion detection," *Future Gener. Comput. Syst.*, vol. 175, Art. no. 108059, Feb. 2026, doi: 10.1016/j.future.2025.108059.

- Sources: https://api.crossref.org/works/10.1016/j.future.2025.108059 ; https://www.sciencedirect.com/science/article/abs/pii/S0167739X25003541 (search snippet only)
- Full author names (Crossref): Shuhua Li, Ruiying Du, Jing Chen, Kun He, Cong Wu, Yebo Feng.
- Online 2025-08-06; issue February 2026.
- Discrepancies: the citation as given had no authors (now supplied). Everything else matches.

**Abstract summary** (from search-engine snippets of the ScienceDirect abstract and highlights; full abstract **not retrieved**):
- *Problem:* Deep-learning NIDSs are opaque, so end-users do not trust or understand alerts. Existing post-hoc explainers can give unfaithful explanations.
- *Method:* A detector and an explainer combined in one architecture. Explanations come from disentangling traffic representations and generating counterfactuals. The output is a human-readable "intrusion profile" that pairs attack information with the explanation.
- *Datasets:* four traffic datasets, per the highlights. The names were not in the retrieved text.
- *Results:* no numbers in the retrieved text.
- *Relevance:* Explainable NIDS, using counterfactuals rather than SHAP. Not federated, SDN or DDoS-specific. Useful for discussing the limits of post-hoc attribution methods such as SHAP (the faithfulness critique).

### [A9] Minh et al. (2025)

**Verified IEEE citation:**
C. Minh, K. Vermeulen, C. Lefebvre, P. Owezarski, and W. Ritchie, "When the weakest model sees the threat: An explainable ensemble learning system for detecting network attacks," *Comput. Netw.*, vol. 273, Art. no. 111730, Dec. 2025, doi: 10.1016/j.comnet.2025.111730.

- Sources: https://api.crossref.org/works/10.1016/j.comnet.2025.111730 ; https://dblp.org/rec/journals/cn/MinhVLOR25.html (search result) ; https://www.sciencedirect.com/science/article/abs/pii/S1389128625006966 (search snippet only)
- Full author names: Céline Minh, Kevin Vermeulen, Cédric Lefebvre, Philippe Owezarski, William Ritchie.
- Online 2025-09-24; issue December 2025.
- Discrepancies: "et al." expanded to 5 authors. Everything else matches.
- Note: a related 2023 conference version exists, "An explainable-by-design ensemble learning system to detect unknown network attacks" (CNSM 2023, same authors). It is a different paper; do not merge the two.

**Abstract summary** (from search-engine snippets of the ScienceDirect abstract; full abstract **not retrieved**):
- *Problem:* Traffic volume exceeds what analysts can review, new attacks keep appearing, and analysts need to know *why* an IDS raised an alarm before acting on it.
- *Method:* Behavioural detection on short time windows of aggregated traffic using several unsupervised detectors. These are often complementary, and a globally weaker detector is sometimes the only one that catches a given attack. A stacking ensemble keeps these "minority reports", and anomaly scores are shown to analysts as heatmaps.
- *Datasets and results:* not in the retrieved text.
- *Relevance:* An explainable, unsupervised ensemble for network attack detection on aggregated windows, which is conceptually close to controller-polled flow statistics. Not federated, not SDN, and not DDoS-specific. It supports using window-aggregated features and explanations aimed at operators.

### [A10] Houssel et al. (2026), eX-NIDS

**Verified IEEE citation:**
P. R. B. Houssel, S. Layeghy, P. Singh, and M. Portmann, "eX-NIDS: A framework for explainable network intrusion detection leveraging large language models," *Comput. Electr. Eng.*, vol. 129, Art. no. 110826, Jan. 2026, doi: 10.1016/j.compeleceng.2025.110826.

- Sources: https://api.crossref.org/works/10.1016/j.compeleceng.2025.110826 ; https://api.semanticscholar.org/graph/v1/paper/DOI:10.1016/j.compeleceng.2025.110826 ; PII S0045790625007694
- Full author names: Paul R.B. Houssel, Siamak Layeghy, Priyanka Singh, Marius Portmann.
- Online 2025-11-12; issue January 2026.
- Discrepancies: (a) authors were missing (now supplied); (b) **"Part B": UNCONFIRMED.** Crossref records volume 129 with no issue or part, and ScienceDirect could not be reached. Keep "Part B" only if you can see it on the ScienceDirect page; otherwise drop it. (c) Journal title is "Computers and Electrical Engineering", not "&".

**Abstract summary** (full abstract via Semantic Scholar):
- *Problem:* Flow-based NIDS alerts are hard to interpret.
- *Method:* Flows the NIDS labels malicious go through a "Prompt Augmenter", which adds context and cyber-threat-intelligence knowledge to the LLM prompt. The LLM then explains why the flow was flagged. This is compared with a Basic-Prompt Explainer baseline that has no added context. Evaluation uses Llama 3 and GPT-4 with a new method for scoring the correctness and consistency of natural-language explanations.
- *Datasets:* not named in the abstract.
- *Results (authors' claims):* augmented LLMs produce accurate and consistent explanations, and augmented prompts improve performance **by over 20%** compared with the Basic-Prompt Explainer.
- *Relevance:* Explainable flow-based NIDS (LLM natural-language explanations, not SHAP). Not federated, SDN or DDoS-specific. Relevant as future work, for example turning SHAP attributions into explanations an operator can read.

---

## Task B: supporting references

### B1. CICDDoS2019 dataset paper (verified)
I. Sharafaldin, A. H. Lashkari, S. Hakak, and A. A. Ghorbani, "Developing realistic distributed denial of service (DDoS) attack dataset and taxonomy," in *Proc. Int. Carnahan Conf. Secur. Technol. (ICCST)*, Chennai, India, Oct. 2019, pp. 1–8, doi: 10.1109/CCST.2019.8888419.
- Source: https://api.crossref.org/works/10.1109/CCST.2019.8888419 (title, authors, pages 1–8, Oct 2019, Chennai). Dataset page: https://www.unb.ca/cic/datasets/ddos-2019.html (HTTP 200).
- Note: the original authors claim the dataset "remedies all current shortcomings". That is their own claim, not an independent audit (see B7).

### B2. Mininet (verified, with notes)
B. Lantz, B. Heller, and N. McKeown, "A network in a laptop: Rapid prototyping for software-defined networks," in *Proc. 9th ACM SIGCOMM Workshop Hot Topics Netw. (HotNets-IX)*, Monterey, CA, USA, Oct. 2010, pp. 1–6, doi: 10.1145/1868447.1868466.
- Source: https://api.crossref.org/works/10.1145/1868447.1868466. Crossref gives the title only as "A network in a laptop" (the subtitle is missing from the metadata) and gives the container as "Proceedings of the 9th ACM SIGCOMM Workshop on Hot Topics in Networks", pp. 1–6, 2010-10-20. Crossref's event field says "Hotnets-X: 10th …", which contradicts its own container title. The 2010 workshop was the 9th (HotNets-IX), so the container title is used. The ACM DL page returned 403. Project site: https://mininet.org/.

### B3. OpenFlow (verified)
N. McKeown, T. Anderson, H. Balakrishnan, G. Parulkar, L. Peterson, J. Rexford, S. Shenker, and J. Turner, "OpenFlow: Enabling innovation in campus networks," *ACM SIGCOMM Comput. Commun. Rev.*, vol. 38, no. 2, pp. 69–74, Apr. 2008, doi: 10.1145/1355734.1355746.
- Source: https://api.crossref.org/works/10.1145/1355734.1355746 (vol. 38, no. 2, pp. 69–74; Crossref issued date 2008-03-31, and the issue is the April 2008 CCR; the title in Crossref is truncated to "OpenFlow").

### B4. OpenFlow Switch Specification 1.3 (verified URL)
Open Networking Foundation, "OpenFlow switch specification, version 1.3.0 (wire protocol 0x04)," ONF TS-006, Jun. 25, 2012. [Online]. Available: https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf
- Verified by downloading the PDF: the cover page reads "OpenFlow Switch Specification / Version 1.3.0 (Wire Protocol 0x04) / June 25, 2012 / ONF TS-006".
- If the project relies on later 1.3.x behaviour, the 1.3.5 spec is also live (HTTP 200): https://opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.3.5.pdf (its cover page was not checked).

### B5. Ryu and os-ken (verified URLs)
- Ryu SDN Framework Community, "Ryu SDN framework documentation." [Online]. Available: https://ryu.readthedocs.io/en/latest/ (HTTP 200). Project site: https://ryu-sdn.org/ ; source: https://github.com/faucetsdn/ryu (HTTP 200; the latest PyPI release is `ryu` 4.34).
- OpenStack, "os-ken: A component-based software defined networking framework for OpenStack," documentation. [Online]. Available: https://docs.openstack.org/os-ken/latest/ (HTTP 200; page title "Welcome to the documentation of os_ken", built from 4.3.0.dev8). PyPI: https://pypi.org/project/os-ken/ (latest release 4.2.2 at time of check; the summary string above is quoted from PyPI). Source: https://opendev.org/openstack/os-ken.
- Give an access date in the report (e.g., "accessed Oct. 28, 2026") and the exact os-ken version the project pins.

### B6. SHAP, XGBoost, Random Forests, scikit-learn (verified)
- S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in *Advances in Neural Information Processing Systems 30 (NIPS 2017)*, I. Guyon *et al.*, Eds. Red Hook, NY, USA: Curran Associates, 2017. [Online]. Available: https://proceedings.neurips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html
  - Source: the NeurIPS proceedings page and its official BibTeX (volume 30, Curran Associates; **the official BibTeX has an empty pages field**). The page range "4765–4774" seen in many citations was **not verified** here, so it is left out.
- S. M. Lundberg, G. Erion, H. Chen, A. DeGrave, J. M. Prutkin, B. Nair, R. Katz, J. Himmelfarb, N. Bansal, and S.-I. Lee, "From local explanations to global understanding with explainable AI for trees," *Nature Mach. Intell.*, vol. 2, no. 1, pp. 56–67, Jan. 2020, doi: 10.1038/s42256-019-0138-9.
  - Source: https://api.crossref.org/works/10.1038/s42256-019-0138-9 (10 authors; this is the TreeSHAP paper, the right citation for `shap.TreeExplainer` on RF/XGBoost).
- T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting system," in *Proc. 22nd ACM SIGKDD Int. Conf. Knowl. Discov. Data Mining (KDD)*, San Francisco, CA, USA, Aug. 2016, pp. 785–794, doi: 10.1145/2939672.2939785.
  - Source: https://api.crossref.org/works/10.1145/2939672.2939785 (Crossref truncates the title to "XGBoost").
- L. Breiman, "Random forests," *Mach. Learn.*, vol. 45, no. 1, pp. 5–32, Oct. 2001, doi: 10.1023/A:1010933404324.
  - Source: https://api.crossref.org/works/10.1023/A:1010933404324
- F. Pedregosa, G. Varoquaux, A. Gramfort, V. Michel, B. Thirion, O. Grisel, M. Blondel, P. Prettenhofer, R. Weiss, V. Dubourg, J. Vanderplas, A. Passos, D. Cournapeau, M. Brucher, M. Perrot, and É. Duchesnay, "Scikit-learn: Machine learning in Python," *J. Mach. Learn. Res.*, vol. 12, no. 85, pp. 2825–2830, 2011. [Online]. Available: https://jmlr.org/papers/v12/pedregosa11a.html
  - Source: the JMLR page ("12(85):2825−2830, 2011", 16 authors). JMLR papers have no DOI.

### B7. Known flaws in CIC datasets (verified)
- G. Engelen, V. Rimmer, and W. Joosen, "Troubleshooting an intrusion detection dataset: The CICIDS2017 case study," in *Proc. IEEE Secur. Privacy Workshops (SPW)*, San Francisco, CA, USA, May 2021, pp. 7–12, doi: 10.1109/SPW53761.2021.00009.
  - Source: https://api.crossref.org/works/10.1109/SPW53761.2021.00009
- M. Lanvin, P.-F. Gimenez, Y. Han, F. Majorczyk, L. Mé, and É. Totel, "Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes," in *Risks and Security of Internet and Systems (CRiSIS 2022)*, Lecture Notes in Computer Science, vol. 13857. Cham, Switzerland: Springer, 2023, pp. 18–33, doi: 10.1007/978-3-031-31108-6_2.
  - Source: https://api.crossref.org/works/10.1007/978-3-031-31108-6_2 (authors, pp. 18–33, 2023, CRiSIS 2022 in Sousse, Tunisia, first online 14 May 2023). The LNCS volume number 13857 comes from a search result describing the Springer book page (https://www.springer.com/book/9783031311079). The Springer page itself redirected to a login and dblp served a bot check, so **13857 is only confirmed from a secondary source**. Check it before submission.
  - Why it matters here: according to a search snippet of this paper, it states that CICIDS2017 **and CICDDoS2019** were both produced with CICFlowMeter, and that the tool's bugs cast doubt on the reliability of both datasets. That is the strongest peer-reviewed statement found that concerns CICDDoS2019. Confirm the exact wording in the full text before quoting it.
- L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen, "Error prevalence in NIDS datasets: A case study on CIC-IDS-2017 and CSE-CIC-IDS-2018," in *Proc. IEEE Conf. Commun. Netw. Secur. (CNS)*, Oct. 2022, pp. 254–262, doi: 10.1109/CNS56114.2022.9947235.
  - Source: Crossref search (`query.bibliographic`); DOI, pages, authors and date taken from the Crossref record.
- R. Flood, G. Engelen, D. Aspinall, and L. Desmet, "Bad design smells in benchmark NIDS datasets," in *Proc. IEEE 9th Eur. Symp. Secur. Privacy (EuroS&P)*, Vienna, Austria, Jul. 2024, pp. 658–675, doi: 10.1109/EuroSP60621.2024.00042.
  - Source: Crossref search record. **Whether CIC-DDoS2019 is among the 7 datasets analysed is UNCONFIRMED.** Check the paper before citing it as a CICDDoS2019 critique; otherwise cite it only for general NIDS-dataset design problems.
- **No CICDDoS2019-specific peer-reviewed labelling or quality audit was found.** The search covered general queries, "CICFlowMeter bugs", and "revisited/corrected CICDDoS2019". The only CICDDoS2019-specific item found was an unresolved GitHub issue on PCAP timestamps versus the published attack schedule (https://github.com/ahlashkari/CICFlowMeter/issues/70), which is not citable as peer-reviewed. The report should say this plainly: the critiques are of the CICFlowMeter tool chain shared with CICDDoS2019, not audits of CICDDoS2019 itself.

### B8. ML-based DDoS detection in SDN (verified)
- R. Braga, E. Mota, and A. Passito, "Lightweight DDoS flooding attack detection using NOX/OpenFlow," in *Proc. IEEE 35th Conf. Local Comput. Netw. (LCN)*, Denver, CO, USA, Oct. 2010, pp. 408–415, doi: 10.1109/LCN.2010.5735752.
  - Source: Crossref; abstract via OpenAlex: flow features are pulled from switches through NOX at low overhead, then classified with Self-Organizing Maps. The authors claim a high detection rate and a low false-alarm rate (no numbers in the abstract). OpenAlex citation count: 731. This is the canonical "controller-polled flow statistics + ML" reference.
- L. Tan, Y. Pan, J. Wu, J. Zhou, H. Jiang, and Y. Deng, "A new framework for DDoS attack detection and defense in SDN environment," *IEEE Access*, vol. 8, pp. 161908–161919, 2020, doi: 10.1109/ACCESS.2020.3021435.
  - Source: Crossref; abstract via OpenAlex and Semantic Scholar: a data-plane trigger flags abnormal flows, a combined K-Means and KNN model classifies them using rate and asymmetry features, and the controller then mitigates. Open access. **The abstract does not mention Mininet or Ryu.** Check the full text before claiming that testbed.
- N. Ahuja, G. Singal, D. Mukhopadhyay, and N. Kumar, "Automated DDOS attack detection in software defined networking," *J. Netw. Comput. Appl.*, vol. 187, Art. no. 103108, Aug. 2021, doi: 10.1016/j.jnca.2021.103108.
  - Source: Crossref; abstract via Semantic Scholar: novel SDN flow features are logged to CSV to build a public SDN dataset, and a hybrid SVC-RF classifier is trained on it. The authors claim **98.8% testing accuracy** with a very low false-alarm rate. **The abstract does not name Mininet or Ryu.** It is widely reported to use them, but that was not verified here.
- Optional (SDN-specific dataset): M. S. Elsayed, N.-A. Le-Khac, and A. D. Jurcut, "InSDN: A novel SDN intrusion dataset," *IEEE Access*, vol. 8, pp. 165263–165284, 2020, doi: 10.1109/ACCESS.2020.3022633. (Source: Crossref.) Ma and Su [A4] reportedly evaluate on it.

---

## Ready-to-paste IEEE reference list

Items marked **[CHECK]** have one detail that is not fully verified; the reason is given inline. Everything else was confirmed against Crossref or the primary page.

[1] R. Carillo, F. Cerasuolo, G. Bovenzi, D. Ciuonzo, and A. Pescapè, "Explainable federated class incremental learning for encrypted network traffic classification," *Comput. Netw.*, vol. 269, Art. no. 111448, Sep. 2025, doi: 10.1016/j.comnet.2025.111448.

[2] R. Kalakoti, S. Nõmm, and H. Bahsi, "Federated learning of explainable AI (FedXAI) for deep learning-based intrusion detection in IoT networks," *Comput. Netw.*, vol. 270, Art. no. 111479, Oct. 2025, doi: 10.1016/j.comnet.2025.111479.

[3] J. P. Sahoo, B. Kar, A. M. Abdelmoniem, and D. Chatzopoulos, "Choir-IDS: A federated learning framework for fidelity-calibrated explainable intrusion detection system for edge-IoT networks," *Inf. Fusion*, vol. 125, Art. no. 103473, Jan. 2026, doi: 10.1016/j.inffus.2025.103473.

[4] J. Ma and W. Su, "Collaborative DDoS defense for SDN-based AIoT with autoencoder-enhanced federated learning," *Inf. Fusion*, vol. 117, Art. no. 102820, May 2025, doi: 10.1016/j.inffus.2024.102820.

[5] A. Tellache, A. Amara Korba, A. Mokhtari, and Y. Ghamri-Doudane, "Collaborative privacy-preserving network intrusion detection: A federated multi-agent reinforcement learning approach," *Comput. Commun.*, vol. 256, Art. no. 108565, Jul. 2026, doi: 10.1016/j.comcom.2026.108565.

[6] W. Wang, Y. Liu, Q. Meng, and Z. Chen, "DDoS attack detection and defense techniques in software defined networks: A survey," *Comput. Sci. Rev.*, vol. 60, Art. no. 100921, May 2026, doi: 10.1016/j.cosrev.2026.100921.

[7] D. Cajaraville-Aboy *et al.*, "CO-DEFEND: Continuous decentralized federated learning for secure DoH-based threat detection," *Comput. Netw.*, vol. 276, Art. no. 111961, Feb. 2026, doi: 10.1016/j.comnet.2025.111961.

[8] S. Li, R. Du, J. Chen, K. He, C. Wu, and Y. Feng, "CANDICE: An explainable and intelligent framework for network intrusion detection," *Future Gener. Comput. Syst.*, vol. 175, Art. no. 108059, Feb. 2026, doi: 10.1016/j.future.2025.108059.

[9] C. Minh, K. Vermeulen, C. Lefebvre, P. Owezarski, and W. Ritchie, "When the weakest model sees the threat: An explainable ensemble learning system for detecting network attacks," *Comput. Netw.*, vol. 273, Art. no. 111730, Dec. 2025, doi: 10.1016/j.comnet.2025.111730.

[10] P. R. B. Houssel, S. Layeghy, P. Singh, and M. Portmann, "eX-NIDS: A framework for explainable network intrusion detection leveraging large language models," *Comput. Electr. Eng.*, vol. 129, Art. no. 110826, Jan. 2026, doi: 10.1016/j.compeleceng.2025.110826. **[CHECK: "Part B" left out because it could not be verified; add it only if ScienceDirect shows it.]**

[11] I. Sharafaldin, A. H. Lashkari, S. Hakak, and A. A. Ghorbani, "Developing realistic distributed denial of service (DDoS) attack dataset and taxonomy," in *Proc. Int. Carnahan Conf. Secur. Technol. (ICCST)*, Chennai, India, Oct. 2019, pp. 1–8, doi: 10.1109/CCST.2019.8888419.

[12] B. Lantz, B. Heller, and N. McKeown, "A network in a laptop: Rapid prototyping for software-defined networks," in *Proc. 9th ACM SIGCOMM Workshop Hot Topics Netw. (HotNets-IX)*, Monterey, CA, USA, Oct. 2010, pp. 1–6, doi: 10.1145/1868447.1868466.

[13] N. McKeown *et al.*, "OpenFlow: Enabling innovation in campus networks," *ACM SIGCOMM Comput. Commun. Rev.*, vol. 38, no. 2, pp. 69–74, Apr. 2008, doi: 10.1145/1355734.1355746.

[14] Open Networking Foundation, "OpenFlow switch specification, version 1.3.0 (wire protocol 0x04)," ONF TS-006, Jun. 2012. [Online]. Available: https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf

[15] Ryu SDN Framework Community, "Ryu SDN framework documentation." [Online]. Available: https://ryu.readthedocs.io/en/latest/ (accessed Oct. 28, 2026).

[16] OpenStack, "os-ken: A component-based software defined networking framework for OpenStack." [Online]. Available: https://docs.openstack.org/os-ken/latest/ and https://pypi.org/project/os-ken/ (accessed Oct. 28, 2026).

[17] S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in *Advances in Neural Information Processing Systems 30 (NIPS 2017)*. Red Hook, NY, USA: Curran Associates, 2017. [Online]. Available: https://proceedings.neurips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html

[18] S. M. Lundberg *et al.*, "From local explanations to global understanding with explainable AI for trees," *Nature Mach. Intell.*, vol. 2, no. 1, pp. 56–67, Jan. 2020, doi: 10.1038/s42256-019-0138-9.

[19] T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting system," in *Proc. 22nd ACM SIGKDD Int. Conf. Knowl. Discov. Data Mining (KDD)*, San Francisco, CA, USA, Aug. 2016, pp. 785–794, doi: 10.1145/2939672.2939785.

[20] L. Breiman, "Random forests," *Mach. Learn.*, vol. 45, no. 1, pp. 5–32, Oct. 2001, doi: 10.1023/A:1010933404324.

[21] F. Pedregosa *et al.*, "Scikit-learn: Machine learning in Python," *J. Mach. Learn. Res.*, vol. 12, no. 85, pp. 2825–2830, 2011. [Online]. Available: https://jmlr.org/papers/v12/pedregosa11a.html

[22] G. Engelen, V. Rimmer, and W. Joosen, "Troubleshooting an intrusion detection dataset: The CICIDS2017 case study," in *Proc. IEEE Secur. Privacy Workshops (SPW)*, San Francisco, CA, USA, May 2021, pp. 7–12, doi: 10.1109/SPW53761.2021.00009.

[23] M. Lanvin, P.-F. Gimenez, Y. Han, F. Majorczyk, L. Mé, and É. Totel, "Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes," in *Risks and Security of Internet and Systems (CRiSIS 2022)*, Lecture Notes in Computer Science, vol. 13857. Cham, Switzerland: Springer, 2023, pp. 18–33, doi: 10.1007/978-3-031-31108-6_2. **[CHECK: LNCS vol. 13857 comes from a secondary source.]**

[24] L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen, "Error prevalence in NIDS datasets: A case study on CIC-IDS-2017 and CSE-CIC-IDS-2018," in *Proc. IEEE Conf. Commun. Netw. Secur. (CNS)*, 2022, pp. 254–262, doi: 10.1109/CNS56114.2022.9947235.

[25] R. Braga, E. Mota, and A. Passito, "Lightweight DDoS flooding attack detection using NOX/OpenFlow," in *Proc. IEEE 35th Conf. Local Comput. Netw. (LCN)*, Denver, CO, USA, Oct. 2010, pp. 408–415, doi: 10.1109/LCN.2010.5735752.

[26] L. Tan, Y. Pan, J. Wu, J. Zhou, H. Jiang, and Y. Deng, "A new framework for DDoS attack detection and defense in SDN environment," *IEEE Access*, vol. 8, pp. 161908–161919, 2020, doi: 10.1109/ACCESS.2020.3021435.

[27] N. Ahuja, G. Singal, D. Mukhopadhyay, and N. Kumar, "Automated DDOS attack detection in software defined networking," *J. Netw. Comput. Appl.*, vol. 187, Art. no. 103108, Aug. 2021, doi: 10.1016/j.jnca.2021.103108.

Optional, if used:

[28] R. Flood, G. Engelen, D. Aspinall, and L. Desmet, "Bad design smells in benchmark NIDS datasets," in *Proc. IEEE 9th Eur. Symp. Secur. Privacy (EuroS&P)*, Vienna, Austria, Jul. 2024, pp. 658–675, doi: 10.1109/EuroSP60621.2024.00042. **[CHECK: citation verified; whether it covers CIC-DDoS2019 is unconfirmed.]**

[29] M. S. Elsayed, N.-A. Le-Khac, and A. D. Jurcut, "InSDN: A novel SDN intrusion dataset," *IEEE Access*, vol. 8, pp. 165263–165284, 2020, doi: 10.1109/ACCESS.2020.3022633.
