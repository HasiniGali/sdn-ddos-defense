// Build report/report.docx from report/facts.json and the chapter specs.
//   node report/build_report.js
const fs = require("fs");
const path = require("path");
const { d, render, styles, numbering, MARGIN, runs } = require("./lib");
const S = require("./chapters_static");
const Rz = require("./chapters_results");

const ROOT = path.join(__dirname, "..");
const facts = JSON.parse(fs.readFileSync(path.join(__dirname, "facts.json"), "utf8"));
const FIG = path.join(ROOT, "results", "figures");

const REFS = [
  'R. Carillo, F. Cerasuolo, G. Bovenzi, D. Ciuonzo, and A. Pescapè, "Explainable federated class incremental learning for encrypted network traffic classification," *Comput. Netw.*, vol. 269, Art. no. 111448, Sep. 2025, doi: 10.1016/j.comnet.2025.111448.',
  'R. Kalakoti, S. Nõmm, and H. Bahsi, "Federated learning of explainable AI (FedXAI) for deep learning-based intrusion detection in IoT networks," *Comput. Netw.*, vol. 270, Art. no. 111479, Oct. 2025, doi: 10.1016/j.comnet.2025.111479.',
  'J. P. Sahoo, B. Kar, A. M. Abdelmoniem, and D. Chatzopoulos, "Choir-IDS: A federated learning framework for fidelity-calibrated explainable intrusion detection system for edge-IoT networks," *Inf. Fusion*, vol. 125, Art. no. 103473, Jan. 2026, doi: 10.1016/j.inffus.2025.103473.',
  'J. Ma and W. Su, "Collaborative DDoS defense for SDN-based AIoT with autoencoder-enhanced federated learning," *Inf. Fusion*, vol. 117, Art. no. 102820, May 2025, doi: 10.1016/j.inffus.2024.102820.',
  'A. Tellache, A. Amara Korba, A. Mokhtari, and Y. Ghamri-Doudane, "Collaborative privacy-preserving network intrusion detection: A federated multi-agent reinforcement learning approach," *Comput. Commun.*, vol. 256, Art. no. 108565, Jul. 2026, doi: 10.1016/j.comcom.2026.108565.',
  'W. Wang, Y. Liu, Q. Meng, and Z. Chen, "DDoS attack detection and defense techniques in software defined networks: A survey," *Comput. Sci. Rev.*, vol. 60, Art. no. 100921, May 2026, doi: 10.1016/j.cosrev.2026.100921.',
  'D. Cajaraville-Aboy *et al.*, "CO-DEFEND: Continuous decentralized federated learning for secure DoH-based threat detection," *Comput. Netw.*, vol. 276, Art. no. 111961, Feb. 2026, doi: 10.1016/j.comnet.2025.111961.',
  'S. Li, R. Du, J. Chen, K. He, C. Wu, and Y. Feng, "CANDICE: An explainable and intelligent framework for network intrusion detection," *Future Gener. Comput. Syst.*, vol. 175, Art. no. 108059, Feb. 2026, doi: 10.1016/j.future.2025.108059.',
  'C. Minh, K. Vermeulen, C. Lefebvre, P. Owezarski, and W. Ritchie, "When the weakest model sees the threat: An explainable ensemble learning system for detecting network attacks," *Comput. Netw.*, vol. 273, Art. no. 111730, Dec. 2025, doi: 10.1016/j.comnet.2025.111730.',
  'P. R. B. Houssel, S. Layeghy, P. Singh, and M. Portmann, "eX-NIDS: A framework for explainable network intrusion detection leveraging large language models," *Comput. Electr. Eng.*, vol. 129, Art. no. 110826, Jan. 2026, doi: 10.1016/j.compeleceng.2025.110826.',
  'I. Sharafaldin, A. H. Lashkari, S. Hakak, and A. A. Ghorbani, "Developing realistic distributed denial of service (DDoS) attack dataset and taxonomy," in *Proc. Int. Carnahan Conf. Secur. Technol. (ICCST)*, Chennai, India, Oct. 2019, pp. 1–8, doi: 10.1109/CCST.2019.8888419.',
  'B. Lantz, B. Heller, and N. McKeown, "A network in a laptop: Rapid prototyping for software-defined networks," in *Proc. 9th ACM SIGCOMM Workshop Hot Topics Netw. (HotNets-IX)*, Monterey, CA, USA, Oct. 2010, pp. 1–6, doi: 10.1145/1868447.1868466.',
  'N. McKeown *et al.*, "OpenFlow: Enabling innovation in campus networks," *ACM SIGCOMM Comput. Commun. Rev.*, vol. 38, no. 2, pp. 69–74, Apr. 2008, doi: 10.1145/1355734.1355746.',
  'Open Networking Foundation, "OpenFlow switch specification, version 1.3.0 (wire protocol 0x04)," ONF TS-006, Jun. 2012. [Online]. Available: https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf',
  'Ryu SDN Framework Community, "Ryu SDN framework documentation." [Online]. Available: https://ryu.readthedocs.io/en/latest/ (accessed Oct. 28, 2026).',
  'OpenStack, "os-ken: A component-based software defined networking framework for OpenStack," version 4.2.2. [Online]. Available: https://docs.openstack.org/os-ken/latest/ (accessed Oct. 28, 2026).',
  'S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in *Advances in Neural Information Processing Systems 30 (NIPS 2017)*. Red Hook, NY, USA: Curran Associates, 2017. [Online]. Available: https://proceedings.neurips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html',
  'S. M. Lundberg *et al.*, "From local explanations to global understanding with explainable AI for trees," *Nature Mach. Intell.*, vol. 2, no. 1, pp. 56–67, Jan. 2020, doi: 10.1038/s42256-019-0138-9.',
  'T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting system," in *Proc. 22nd ACM SIGKDD Int. Conf. Knowl. Discov. Data Mining (KDD)*, San Francisco, CA, USA, Aug. 2016, pp. 785–794, doi: 10.1145/2939672.2939785.',
  'L. Breiman, "Random forests," *Mach. Learn.*, vol. 45, no. 1, pp. 5–32, Oct. 2001, doi: 10.1023/A:1010933404324.',
  'F. Pedregosa *et al.*, "Scikit-learn: Machine learning in Python," *J. Mach. Learn. Res.*, vol. 12, no. 85, pp. 2825–2830, 2011. [Online]. Available: https://jmlr.org/papers/v12/pedregosa11a.html',
  'G. Engelen, V. Rimmer, and W. Joosen, "Troubleshooting an intrusion detection dataset: The CICIDS2017 case study," in *Proc. IEEE Secur. Privacy Workshops (SPW)*, San Francisco, CA, USA, May 2021, pp. 7–12, doi: 10.1109/SPW53761.2021.00009.',
  'M. Lanvin, P.-F. Gimenez, Y. Han, F. Majorczyk, L. Mé, and É. Totel, "Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes," in *Risks and Security of Internet and Systems (CRiSIS 2022)*, LNCS, vol. 13857. Cham, Switzerland: Springer, 2023, pp. 18–33, doi: 10.1007/978-3-031-31108-6_2.',
  'L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen, "Error prevalence in NIDS datasets: A case study on CIC-IDS-2017 and CSE-CIC-IDS-2018," in *Proc. IEEE Conf. Commun. Netw. Secur. (CNS)*, 2022, pp. 254–262, doi: 10.1109/CNS56114.2022.9947235.',
  'R. Braga, E. Mota, and A. Passito, "Lightweight DDoS flooding attack detection using NOX/OpenFlow," in *Proc. IEEE 35th Conf. Local Comput. Netw. (LCN)*, Denver, CO, USA, Oct. 2010, pp. 408–415, doi: 10.1109/LCN.2010.5735752.',
  'L. Tan, Y. Pan, J. Wu, J. Zhou, H. Jiang, and Y. Deng, "A new framework for DDoS attack detection and defense in SDN environment," *IEEE Access*, vol. 8, pp. 161908–161919, 2020, doi: 10.1109/ACCESS.2020.3021435.',
  'N. Ahuja, G. Singal, D. Mukhopadhyay, and N. Kumar, "Automated DDOS attack detection in software defined networking," *J. Netw. Comput. Appl.*, vol. 187, Art. no. 103108, Aug. 2021, doi: 10.1016/j.jnca.2021.103108.',
];

function titlePage() {
  const P = (text, size, opts = {}) => new d.Paragraph({ alignment: d.AlignmentType.CENTER,
    spacing: { after: opts.after ?? 200 }, children: [new d.TextRun({ text, size, bold: opts.bold, color: opts.color })] });
  const team = [["Register No.", "Name"], ["25BCE0507", "Ayush Biswas"], ["25BAI0022", "Ustat Kaur"], ["25BCE2096", "Gali Hasini"]];
  const w = [2600, 3600];
  return [
    P("", 22, { after: 1600 }),
    P("Intelligent DDoS Detection and Mitigation Framework for SDN Networks", 40, { bold: true, color: "1F3864", after: 400 }),
    P("Project report — Group 9", 28, { after: 900 }),
    new d.Table({ alignment: d.AlignmentType.CENTER, width: { size: w[0] + w[1], type: d.WidthType.DXA }, columnWidths: w,
      rows: team.map((r, i) => new d.TableRow({ children: r.map((t, j) => new d.TableCell({
        width: { size: w[j], type: d.WidthType.DXA }, margins: { top: 80, bottom: 80, left: 120, right: 120 },
        shading: i === 0 ? { fill: "E8EEF6", type: d.ShadingType.CLEAR, color: "auto" } : undefined,
        children: [new d.Paragraph({ children: [new d.TextRun({ text: t, bold: i === 0, size: 24 })] })] })) })) }),
    P("", 22, { after: 900 }),
    P("Stack: Mininet + Open vSwitch + os-ken (Ryu) + Python ML", 22, { after: 120 }),
    P("Data: CICDDoS2019 and controlled Mininet attack/benign traces", 22, { after: 120 }),
    P("October 2026", 22),
    new d.Paragraph({ children: [new d.PageBreak()] }),
  ];
}

function references() {
  return [
    new d.Paragraph({ heading: d.HeadingLevel.HEADING_1, children: [new d.TextRun("References")] }),
    ...REFS.map((r) => new d.Paragraph({ numbering: { reference: "refs", level: 0 }, spacing: { after: 80 },
      children: runs(r, { size: 19 }) })),
  ];
}

const spec = [
  ...Rz.abstract,
  { type: "pagebreak" },
  { type: "toc" },
  { type: "pagebreak" },
  ...S.intro, ...S.background, ...S.architecture, ...S.design, ...S.implementation,
  ...S.datasets, ...S.setup,
  ...Rz.results, ...Rz.discussion, ...Rz.conclusion,
  { type: "raw", items: references() },
  ...Rz.appendices,
];

const doc = new d.Document({
  creator: "Group 9", title: "Intelligent DDoS Detection and Mitigation Framework for SDN Networks",
  styles, numbering, features: { updateFields: true },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 },
      margin: { top: 1200, bottom: 1200, left: MARGIN, right: MARGIN } } },
    footers: { default: new d.Footer({ children: [new d.Paragraph({ alignment: d.AlignmentType.CENTER,
      children: [new d.TextRun({ children: [d.PageNumber.CURRENT], size: 18 })] })] }) },
    children: [...titlePage(), ...render(spec, facts, FIG)],
  }],
});

d.Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(path.join(__dirname, "report.docx"), buf);
  console.log("wrote report/report.docx");
});
