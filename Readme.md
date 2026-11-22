# UPLOAD2SHELL IMPACT ANALYSIS

CVE-2026-125396 | Use-after-free in Ghostscript's PostScript font handling that gets around -dSAFER (command execution as the account running Ghostscript) | CVSS 3.1: 7.8 High; CVSS 4.0: 8.5 High (CVE record) | Fixed in Ghostscript 10.08.0

Reported by Paulos Yibelo. Fixed by Ken Sharp of Artifex.

Data cut-off: 22 November 2026, 12:30 UTC. Things are still moving, so check NVD, CISA KEV, EPSS and your distro or vendor advisory again before you act on anything here.

---

## EXECUTIVE SUMMARY

### The Upload2Shell situation at a glance

- **What:** A use-after-free in the part of Ghostscript that handles PostScript fonts, tracked as CVE-2026-125396 (CWE-648, Incorrect Use of Privileged APIs). Ghostscript is the program many servers use to turn PDF, PostScript and EPS files into images or print output. The CVE record says "Ghostscript before 10.08.0 contains a -dSAFER bypass vulnerability" and "Attackers can supply crafted PostScript or PDF documents". In plain words: a privileged internal step is reached without proper checks, which leads to a use-after-free and arbitrary code execution. -dSAFER is Ghostscript's built-in sandbox switch, and this bug gets around it. The researcher, Paulos Yibelo, gave the bug the name Upload2Shell. The CVE record gives it no nickname, and its title is a plain description. The researcher says the flaw is in the Type 1 font loader and that a crafted document can run commands as the rendering process (third party claim, not confirmed by Artifex).
- **Risk level:** Our tiers are our reading, not the CVE's. The CVE itself is High (7.8 on CVSS 3.1, 8.5 on CVSS 4.0), never Critical. CRITICAL (our reading) for an affected Ghostscript that untrusted people can reach without a login: CUPS print servers with a shared queue that accepts anonymous jobs from untrusted networks, Roundcube before 1.6.20 or 1.7.5 with ImageMagick present, WordPress sites with the public-upload plugins the researcher names on hosts that have both Imagick and Ghostscript, and any application that passes anonymous uploads or email attachments to ImageMagick, GraphicsMagick, Pillow EPS loading or Ghostscript. HIGH (our reading) for the same paths behind a login, and for internal document pipelines such as MediaWiki with PdfHandler, Paperless-ngx (inferred) and Nextcloud with the PDF or PostScript preview providers switched on. LOW for hosts without Ghostscript, hosts where nothing untrusted reaches it, and fixed builds. Why we rate above the CVSS 7.8: CVSS scores Ghostscript as a local file processor (attack vector Local in both vectors), while the remote path comes from the application in front of it, and the researcher reports command execution in the setups tested.
- **Impact:** Command execution as the account running Ghostscript. The researcher names lp for CUPS and www-data for web and mail setups (third party). The CISA ADP entry rates Technical Impact "total". It is not root by itself (our reading, inferred from the accounts the researcher names), but the account can reach whatever the application can reach.
- **Status:** Fixed upstream in Ghostscript 10.08.0, released on 8 September 2026. The CVE was published on 9 November and the researcher's write-up is dated 21 November, so the news is the disclosure, not a new patch. No attacks reported at the cut-off. The CVE is not in CISA's Known Exploited Vulnerabilities catalog (KEV). A partial public proof exists: the researcher's write-up shows a memory-write step, not a full command-execution chain. Debian 13 and 12 have fixed builds. Ubuntu has not confirmed a fix on its CVE page. Red Hat has no record. SUSE Linux Enterprise and Amazon Linux are still open. openSUSE Tumbleweed lists a released fixed build.
- **Who's safe:** Hosts on Ghostscript 10.08.0, or on a distro build that carries the fix, with every long-running process restarted since the upgrade. Hosts with no Ghostscript installed have no path. Containers and bundled applications that carry their own Ghostscript stay vulnerable until their own image or bundle is updated (the researcher and The Hacker News both say so).
- **Who's at risk:** Any host or image running Ghostscript before 10.08.0, without a distro backport, where an untrusted PostScript, EPS or PDF file can reach it. That includes files that carry an image extension, because the researcher says the extension does not matter. Print servers, webmail, WordPress sites with public upload forms, wikis and document systems are the paths the researcher tested (the table under Application paths that reach Ghostscript has the detail). The researcher also says a Google production service was reached and that Google mitigated its affected path on 10 November 2026. The Hacker News reports the same. Neither claim comes with a Google statement in our sources, and it does not mean Google was breached.

*Sources: the CVE record (including the CISA ADP entry), the Artifex fix commit, Ghostscript release notes, NVD, the researcher's write-up, The Hacker News, the oss-security list, Debian, Ubuntu, SUSE, Amazon Linux and Red Hat pages, the CISA KEV feed, the FIRST EPSS API*

### What an affected Ghostscript means for your organization

The bug sits in Ghostscript, but most organizations do not run Ghostscript on purpose. It arrives inside something else: the print service, the webmail server, the image resizer behind an upload form, the wiki thumbnailer. So the first question is not "do we use Ghostscript?" but "does anything on our hosts or in our images call it, and can an outsider hand that thing a file?" The Hacker News describes Ghostscript as the interpreter that many Linux servers use to convert uploaded PDFs, PostScript files and images into other formats, often without the application calling it directly.

Why the file does not have to look like PostScript. ImageMagick reads the first bytes of a file and sends anything starting with the PostScript or PDF signature to Ghostscript, whatever the extension says (inferred from ImageMagick's source files). Pillow's EPS plugin works the same way, by content (code in Pillow's own file). The researcher says the same of Pillow, Imagick, libvips and Qt plugins. So an upload form that accepts only PNG or JPG can still pass a PostScript file to Ghostscript if the content is what the converter sees.

Three things about the way people will read this:

- The CVE's Local attack vector is real for Ghostscript alone, but the researcher's tests reached Ghostscript over the network through print jobs, email and web uploads. The Hacker News reports the same.
- -dSAFER is not a mitigation. The bug gets around it. Ghostscript has had SAFER on by default since 9.50, every ImageMagick delegate line that starts Ghostscript already passes it, and so does the Pillow EPS plugin, so the default setup is the attacked setup. Turning it off with -dNOSAFER makes things worse.
- Application fixes do not replace the Ghostscript fix. WordPress 7.0.4 and 6.9.7 fix CVE-2026-65640, and Roundcube 1.6.20 and 1.7.5 fix CVE-2026-114727. Each closes one route. The Hacker News says the WordPress fix and the Ghostscript fix cover different points in the same chain, so updating one does not remove the need for the other.

If an attacker gets this working against one of your hosts, they can:

- Run commands as the account that runs Ghostscript (for example lp or www-data, per the researcher).
- Reach whatever that account can reach: uploaded files, mail, application configuration and secrets, and the databases and internal services the application talks to.

We found no published indicators of compromise from Artifex, the CVE record or the researcher, so there is nothing to match against yet.

Real-world context: Artifex committed the fix on 2 September 2026 and released Ghostscript 10.08.0 on 8 September. The release notes say "This release addresses a number of potential security issues" and name no CVE. The CVE was reserved and published on 9 November (VulnCheck is the CNA). NVD followed on 10 November, and CISA's ADP entry the same day. The researcher's write-up is dated 21 November, and the oss-security announcement is listed on 21 November. The Hacker News wrote it up on 22 November. The gap is about 9 to 11 weeks between the fix and the public detail. Jan Schaumann wrote on oss-security (third party opinion): "If GS published a fix on 2026-09-08, then we should assume that this vulnerability was public as of that date." Our reading is the same for planning: assume the bug has been public since the fix shipped. The exact time the commit became public is not verified.

No attacks reported at the cut-off. The Hacker News says "there have been no reports of it being used in attacks" (third party, not CISA or Artifex). CISA's SSVC entry says Exploitation none as of 10 November, and the CVE is not in KEV. The EPSS score is 0.00164 (0.16 percent, percentile 0.056) as of 21 November. EPSS is a one-day-old model score, not evidence of safety. The Hacker News also reports that the public proof fails on the patched 10.08.0 build before it gets that far.

A GitHub search at the cut-off returned 3 repositories for each of the queries "CVE-2026-125396" and "upload2shell", all created on 22 November. We did not open them, so what they contain is unknown, and the search can undercount. Running unknown proof-of-concept code is a common way to get compromised, so leave them alone. We could not verify any Metasploit or Nuclei check, or any rule from GreyNoise, Tenable, Qualys, Rapid7 or WAF vendors (COULD NOT VERIFY). Reports of attacks that appear in news results for other Ghostscript bugs are not about this CVE.

*Sources: the CVE record, the Artifex fix commit and release notes, the researcher's write-up, The Hacker News, the oss-security list, Ghostscript usage documentation (SAFER), ImageMagick and Pillow source files, the WordPress and Roundcube advisories, the CISA KEV feed, the FIRST EPSS API, GitHub repository search (counts only)*

### Immediate actions for Ghostscript exposure

#### LOCATE EVERY GHOSTSCRIPT (Hour 1)

1. List the hosts, containers and applications that have Ghostscript: print servers, webmail, WordPress and other CMS hosts, wikis, document and OCR systems, and any image or PDF conversion job. Include the images you build yourself.
2. Get the version on each: `gs --version`, and the package version with your package manager. Distro builds keep the old number after a backport, so judge Debian and Ubuntu packages by the package version in the table under Where the Ghostscript fix comes from. The Quick status check has the commands.
3. Mark which of them can receive a file from an outsider: an anonymous upload form, inbound mail, a shared print queue. Those are the CRITICAL tier (our reading). Internet-facing and unauthenticated ones come first.
4. Check CUPS hosts for shared queues. The Quick status check shows the sharing settings without changing them.

#### PATCH AND RESTART (Day 1)

1. Install Ghostscript 10.08.0, or your distro's fixed package where one exists. Red Hat, SUSE Linux Enterprise and Amazon Linux had no fixed package at the cut-off, and Ubuntu had not confirmed one, so watch the vendor page. The commands are under the mitigation steps in a later part of this analysis.
2. Update every container image and application bundle that carries its own Ghostscript. Updating the host does not touch them.
3. Restart long-running services that load the Ghostscript library, for example PHP-FPM with Imagick (inferred, our reading). A fresh gs started for each job picks up the new package on its own.
4. Where no fix can be installed yet, apply the stopgaps from the mitigation steps: block the ImageMagick delegates, stop sharing CUPS queues with untrusted networks, and contain document conversion. These are stopgaps, not fixes.

#### LOOK FOR COMPROMISE (Day 2)

1. Look for gs processes running as web or print users, and for shells or unexpected child processes under gs or under a converter that calls it.
2. Look for stored uploads or mail attachments whose content is PostScript, EPS or PDF behind an image extension.
3. Review print job logs on shared CUPS queues for jobs from unexpected addresses or with no authenticated user.
4. We found no public indicators, so a clean result does not prove safety. If anything looks off, treat the host as compromised and rotate every secret the account can reach.

### Business impact of an unpatched Ghostscript

Financial risk:

- No confirmed compromise has been reported, so there is no incident cost to quote for this bug.
- The fix itself is a package update and a service restart. The costly cases are the ones with no confirmed fix yet: Red Hat family, SUSE, Amazon Linux and Ubuntu hosts, plus images and bundles that carry their own copy.
- Finding every copy of Ghostscript is the hidden cost. It sits inside print services, webmail, CMS plugins and container images, and a base image can carry an old build into every new instance.

Operational risk:

- Restarting services that load the Ghostscript library takes those services briefly offline. Plan the windows.
- Blocking ImageMagick delegates stops PDF and PostScript to image conversion that an application may need, and it does not protect applications that call Ghostscript directly, such as CUPS, MediaWiki and Paperless-ngx (our reading).
- Version scanners will be noisy. A remote check cannot see whether a distro backport is installed, so a flagged host may already carry the fix.
- No public WAF or detection rule for this bug was found in our sources, and we found no public indicators (COULD NOT VERIFY for vendor rules). Do not count on one.

Legal risk:

- If a compromised host holds personal data, breach notification clocks start when you become aware of the breach. The deadlines by jurisdiction are in COMPLIANCE & LEGAL REQUIREMENTS.

*Sources: the CVE record, the researcher's write-up, The Hacker News, Debian, Ubuntu, Red Hat, SUSE and Amazon Linux pages, ImageMagick and CUPS documentation, our reading of how the applications call Ghostscript*

---

## RISK DASHBOARD

### Severity metrics for CVE-2026-125396

| Metric | Rating | What it means |
| --- | --- | --- |
| **Overall risk (our reading)** | CRITICAL for an affected Ghostscript reachable with no login, HIGH behind a login or in internal document pipelines, LOW with no Ghostscript or no untrusted input | Our tiers, not the CVE's. The CVE is High: CVSS 3.1 7.8 and CVSS 4.0 8.5, both from the CNA (VulnCheck). The tier definitions and the reason we rate above CVSS are in the executive summary |
| **Attack vector** | LOCAL in both vectors, NETWORK in the researcher's tests | CVSS scores Ghostscript as a local file processor. The researcher says tests reached it over the network through print jobs, email and web uploads, and The Hacker News reports the same |
| **Attack complexity** | LOW | AC:L in both vectors |
| **Authentication needed** | NONE in the CVSS vectors, depends on the application | PR:N in both. WordPress core needs an Author or higher login. The public-upload plugin paths and the CUPS and Roundcube paths need none, per the researcher |
| **User interaction** | REQUIRED (UI:R in 3.1, UI:P in 4.0) | Someone or something has to open or process the file. In the researcher's tests that was automatic: a print job, a thumbnail, an upload handler |
| **Reach** | ANY PATH THAT PASSES POSTSCRIPT, EPS OR PDF TO GHOSTSCRIPT | Applies to files with an image extension too, because converters read the content (inferred). Containers and bundles with their own Ghostscript are separate |
| **Patch available** | YES upstream, Debian 13 and 12, openSUSE Tumbleweed, NO confirmed for Ubuntu, Red Hat, SUSE Linux Enterprise and Amazon Linux | Ghostscript 10.08.0 came out on 8 September 2026. Older release lines have no upstream backport seen. Plugin fixed versions: none stated by any source we saw |
| **Active exploitation** | NO ATTACKS REPORTED AT THE CUT-OFF | The Hacker News says there are no reports of use in attacks. CISA SSVC Exploitation none. Not in CISA KEV (feed released 20 November 2026). A partial public proof exists |
| **EPSS** | 0.00164 (0.16 percent), percentile 0.056 | Score date 21 November 2026. A one-day-old model score, not evidence of safety |
| **NVD record** | AWAITING ANALYSIS, NO NVD SCORE | Published 10 November 2026, last modified 22 November at 05:18 UTC. Only the VulnCheck secondary score shows |

Ratings by source:

| Source | Rating | Note |
| --- | --- | --- |
| CVE record (VulnCheck, the CNA) | High: CVSS 3.1 7.8, CVSS 4.0 8.5 | 3.1 vector CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H. 4.0 vector CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N. Weakness CWE-648 |
| CISA ADP (Vulnrichment, 10 November) | SSVC: Exploitation none, Automatable no, Technical Impact total | SSVC 2.0.3 |
| NVD | Status "Awaiting Analysis" | No NVD score of its own |
| SUSE | Important | "This issue is currently rated as having important severity." |
| Amazon Linux | Important, CVSS 7.8 | From its CVE page |
| Ubuntu | Medium priority, CVSS 3 score 7.8 High | Ubuntu's own priority scale |
| Debian | No urgency given | The tracker gives none |
| Red Hat | No record | Its security data API returned "Not Found" at 12:45 UTC |
| EPSS | 0.00164 (percentile 0.056) | 21 November 2026 |
| CISA KEV | Not listed | 0 matches in 1790 entries. The only Ghostscript entry we saw is CVE-2017-8291 |

Our reading: treat it as CRITICAL where an affected Ghostscript is reachable with no login, and HIGH behind a login or inside internal document pipelines. Reasons to rate up: the fix has been public since 8 September at the latest, the path from an upload, an email or a print job to Ghostscript is common and often invisible, the researcher reports command execution in the setups it tested (a claim, not confirmed by us), and CISA rates Technical Impact total. Reasons to hold back: no attacks reported at the cut-off, EPSS is low, CISA SSVC says Automatable no, the CVE is not in KEV, no full command-execution chain is public, the researcher marks each per-application exploit "Not published", and every tested result is a researcher claim. We keep the CVE's own rating at High and never call it Critical. The CRITICAL tier is ours.

*Sources: the CVE record (VulnCheck and the CISA ADP entry), NVD, the Debian, Ubuntu, SUSE, Amazon Linux and Red Hat pages, the CISA KEV feed, the FIRST EPSS API, the researcher's write-up, The Hacker News*

### Affected versions: quick lookup for Ghostscript

| Release | Status on 22 November 2026 | Affected releases | Fixed in | Released |
| --- | --- | --- | --- | --- |
| Ghostscript 10.08.0 | Current, has the fix | None for this CVE | 10.08.0 | 8 September 2026 |
| Ghostscript before 10.08.0 (upstream) | Affected | Releases before 10.08.0 per the CVE record. No start version is given, so we COULD NOT VERIFY the first vulnerable release | 10.08.0 | 10.07.1 on 19 May 2026, 10.07.0 on 16 March 2026, 10.06.0 on 9 September 2025 |
| Older release lines (for example 10.05.x) | No upstream fix seen | Fixed only by a distro backport | Distro build, with the old version number kept | 10.05.1 on 29 April 2025, 10.05.0 on 12 March 2025 |
| Debian 13 trixie | Fixed by backport | 10.05.1~dfsg-1+deb13u1 and older | 10.05.1~dfsg-1+deb13u2 or later | Current build deb13u3 |
| Debian 12 bookworm | Fixed in the security repository only | 10.0.0~dfsg-11+deb12u8 is still marked vulnerable | 10.0.0~dfsg-11+deb12u9 | Via DLA-4914-1 (Debian LTS) |

Notes on the table:

- The CVE record lists ArtifexSoftware ghostpdl, version 0 up to but not including 10.08.0 (a custom range), with a CPE range of versionEndExcluding 10.08.0. No start version is given anywhere. The first vulnerable release COULD NOT VERIFY. Say "before 10.08.0" and no more.
- Distro packages do not follow upstream numbers (inferred). So `gs --version` showing 10.05.1 does not mean vulnerable on Debian. Judge distro builds by the package version, not by upstream numbers.
- The fix is Artifex commit 1484854e0c8ddfda1baa4ad4cd965b8a9790aa81, dated 2 September 2026 at 11:04 UTC, one file changed. It adds operand type checks in the font handling code. Ken Sharp's commit message says Artifex is working to eliminate that internal step or at least minimise its use, and that this is still a work in progress. The Hacker News quotes Ken Sharp calling that step "an ancient piece of code well known to be a vulnerability, but difficult to eradicate" (third party, WEAK: quoted from a bug report we could not open). Artifex bug 709684 is cited by the CVE record, and its public status COULD NOT VERIFY.
- Ghostscript 10.08.0 fixes several other CVEs. Only CVE-2026-125396 is Upload2Shell. CVE-2026-39919 (a heap-based buffer overflow in the JPEG 2000 output adapter, CVSS 9.8 on 3.1) is a different flaw. CVE-2026-101258 is a separate -dSAFER bypass published on 6 October 2026. CVE-2026-103226 is a font memory bug. Do not merge their facts with this CVE.
- ImageMagick, GraphicsMagick, LibreOffice and Nextcloud have no project statement on this bug in our sources. "Fixed" for them means a patched Ghostscript or a blocked delegate. LibreOffice exposure is UNKNOWN, no source.

Quick status check:

```bash
# Ghostscript version (on a host, or in a container with docker exec <container> sh -c 'gs --version')
gs --version
# ImageMagick 7: which policy files load, and whether delegates are blocked
magick identify -list policy
# ImageMagick 6
identify -list policy
# Debian and Ubuntu: installed package version
dpkg -s ghostscript | grep '^Version'
# RHEL family, SUSE and Amazon Linux: installed package version
rpm -q ghostscript
# Alpine: installed package version
apk info -v | grep ghostscript
# Homebrew: installed version
brew list --versions ghostscript
# CUPS: current sharing settings, one name=value per line, changes nothing (look at _share_printers and _remote_any)
cupsctl
# CUPS: list the queues
lpstat -v
```

- Vulnerable if `gs --version` is below 10.08.0 and the build is not distro-patched. Debian 13 needs 10.05.1~dfsg-1+deb13u2 or later. Debian 12 needs 10.0.0~dfsg-11+deb12u9 or later from the security repository. For Ubuntu, nothing is confirmed (see the table under Where the Ghostscript fix comes from).
- In the policy listing, a delegate rule with pattern "*" and rights none means ImageMagick cannot start Ghostscript. Each policy file that loads is printed with its path (our reading).
- In the CUPS output, the _share_printers and _remote_any settings show whether the print service is shared with or open to other networks (our reading of the setting names). Whether a queue accepts anonymous jobs is a separate question.
- Containers carry their own Ghostscript. Run the version check inside each container and check images separately from the host.
- A long-running process that loaded the Ghostscript library keeps the old copy in memory after an upgrade (inferred). The assessment part of this analysis has a read-only way to list them.

*Sources: the CVE record, the Artifex fix commit, Ghostscript release notes and releases page, Debian security tracker, DSA-6516-1 and DLA-4914-1, The Hacker News, dpkg, rpm, apk, Homebrew and CUPS documentation*

### Where the Ghostscript fix comes from

Two rules decide whether you are fixed. First, a distro package can carry the fix under an old version number, so compare package versions, not upstream numbers. Second, a long-running process only picks up the fix after a restart. "Not confirmed" means we found no statement that a fixed package is published, even where a source points to one.

| Platform | Status on 22 November 2026 | Fixed package or version | Notes |
| --- | --- | --- | --- |
| Upstream (Ghostscript) | Fixed | 10.08.0 (8 September 2026) | The release notes name no CVE: "This release addresses a number of potential security issues." |
| Debian 13 trixie | Fixed by backport | 10.05.1~dfsg-1+deb13u3 shows "fixed". First fixed version 10.05.1~dfsg-1+deb13u2 via DSA-6516-1 | DSA-6516-1 references CVE-2026-125396 and CVE-2026-39919. Advisory dates not captured (COULD NOT VERIFY), so none are given |
| Debian 12 bookworm | Fixed only in the security repository | 10.0.0~dfsg-11+deb12u9 via DLA-4914-1 | The release pocket version deb12u8 is still marked vulnerable. The security repository must be enabled. The Hacker News lists bookworm as "listed as vulnerable" in the researcher's survey (third party) |
| Debian forky and sid | Fixed | 10.08.0~dfsg-2 (first fixed 10.08.0~dfsg-1) | |
| Ubuntu | NOT CONFIRMED FIXED | None confirmed. Ubuntu's CVE page says "Needs evaluation" for all seven releases (26.10, 26.04 LTS, 24.04 LTS, 22.04 LTS, 20.04 LTS, 18.04 LTS, 16.04 LTS) | Ubuntu shipped a Ghostscript notice on 21 October (USN-8949-1) that the researcher says covers this bug. Ubuntu's own CVE page does not yet say so. The notice text lists "Paulos Yibelo discovered that Ghostscript did not properly validate certain operands when loading fonts", but the CVE number is cut off in our copy (likely this CVE, inferred) |
| Red Hat | NO RECORD | None | Security data API returned "Not Found" at 12:45 UTC. The Hacker News says the researcher did not establish whether current Red Hat, Rocky Linux, AlmaLinux, Oracle Linux or stable Fedora packages carry the fix. No Red Hat statement at the cut-off |
| SUSE | Mostly open. Tumbleweed released | openSUSE Tumbleweed: ghostscript 10.08.0-5.1 or later (patch name openSUSE-Tumbleweed-2026-12528). SUSE Linux Enterprise: none released | 21 product rows "In progress" and none "Resolved". SUSE Linux Enterprise 12 SP5 and 15 SP4 to SP7 builds are listed as "in QA", not released. Many rows show "Affected", for example openSUSE Leap 16.0. No SUSE-SU advisory seen |
| Amazon Linux | Pending | None | AL2, AL2023 and AL2027 Preview ghostscript "Pending Fix". AL2 ghostscript-chinese and ghostscript-fonts "Not Affected". The Hacker News lists AL2 as "fix pending" in the researcher's survey (third party), which matches the Amazon page |
| Alpine | Edge only (inferred) | edge ghostscript 10.08.0-r0 | The security database has no mapping for this CVE. v3.22 and older stable are not fixed in the database (newest fix there is 10.05.1-r0) |
| Fedora | rawhide only (inferred) | 10.08.0-1.fc46 | No advisory checked. Stable branches not checked |
| Arch and Homebrew | Fixed (inferred) | Arch extra 10.08.0-1, Homebrew stable 10.08.0 | Arch build date 8 September 2026 |
| ImageMagick, GraphicsMagick | No statement | None | Nothing is fixed "in ImageMagick". Fix Ghostscript, or block the delegate |
| WordPress core | Separate fix | 7.0.4 and 6.9.7 (CVE-2026-65640) | Closes one route and needs a login. Ghostscript still needs its own fix |
| Roundcube | Separate hardening | 1.6.20 and 1.7.5 (CVE-2026-114727) | App-level hardening the researcher links to this chain. The advisory does not name Ghostscript or CVE-2026-125396 |
| WordPress plugins (Forminator, Essential Addons for Elementor) | No fixed version stated | None | The researcher says a report went to the plugin teams. No source we checked gives a fixed version |

The biggest gaps are Ubuntu, Red Hat, SUSE and Amazon Linux, where an unconfirmed fix leaves the stopgaps as the only option, and every image or bundle with its own Ghostscript. The Hacker News puts it this way: "Coverage across Linux distributions is uneven." (third party). At the 12:45 UTC re-check, nothing had changed in the CVE record, NVD, EPSS, KEV, Ubuntu, Red Hat, Debian, SUSE or Amazon Linux pages. The GitHub search count had risen to 3 per query.

*Sources: vendor and distro pages and trackers as of 22 November 2026 (Ghostscript release notes, Debian security tracker, DSA-6516-1, DLA-4914-1, Ubuntu CVE page and USN-8949-1, Red Hat security data API, SUSE CVE page, Amazon Linux Security Center, Alpine, Fedora, Arch and Homebrew package data, the WordPress and Roundcube advisories), The Hacker News, the researcher's write-up*

### Application paths that reach Ghostscript

Only paths that hand Ghostscript an untrusted file matter, so what calls it tells you which hosts to patch first. The bug is in Ghostscript, not in these applications, and the fix is the same everywhere: a fixed Ghostscript and a restart. Evidence levels: C means confirmed by the project's own advisory or code, R means a researcher claim (third party, attributed), I means inferred from code by us.

| Application | What we found | Condition | Tier (our reading) |
| --- | --- | --- | --- |
| CUPS print servers | R: on Debian 13 (Ghostscript 10.05.1~dfsg-1+deb13u1) an anonymous print job to a shared network queue ran a command as lp, one remote run plus 20 of 20 local conversions. I: cups-filters passes -dSAFER to Ghostscript in its filter path | A shared queue that accepts jobs without authentication from an untrusted network. Debian 13 is the only tested distro | CRITICAL |
| Roundcube | R: version 1.7.2, an external sender's attachment thumbnailed when the recipient views the message, command as www-data, 5 of 5 trials, no click. C: 1.6.20 and 1.7.5 fix unsafe image handling under CVE-2026-114727 | ImageMagick present and Ghostscript present. A tested ImageMagick delegate was required | CRITICAL |
| WordPress public-upload plugins | R only: Forminator 1.55.1 with a signed-out public PDF form, and Essential Addons for Elementor Lite 6.7.0 with a signed-out public Login/Register widget that has an upload field. 5 of 5 HTTP trials each, command as www-data, on WordPress 7.0.2 and Ghostscript 10.05.1 | Imagick and Ghostscript on the host. Public form enabled | CRITICAL |
| WordPress core | C: WordPress says a malicious Postscript upload by an Author level user or higher can lead to remote code execution where Imagick and Ghostscript are in use. Fixed in 7.0.4 and 6.9.7 (CVE-2026-65640) | A login with Author rights or higher, or a Contributor granted upload_files | HIGH |
| Pillow EPS loading | C (Pillow's source): the EPS plugin is content-based, registered by default, and calls Ghostscript with -dSAFER only when an app loads attacker bytes and gs is installed. The researcher traces more Python web apps that open images with Pillow, mostly from reading their code (R, traced in code, not tested) | An app that opens untrusted images and a gs binary on the host. The extension does not matter | CRITICAL if anonymous |
| MediaWiki PdfHandler | I: the extension calls /usr/bin/gs with -dSAFER for PDF thumbnails. R: reproduced on MediaWiki 1.46.0 on a wiki set up for anonymous PDF uploads (5 of 5, www-data). No Wikimedia statement found | PdfHandler enabled and uploads permitted | HIGH, CRITICAL if anonymous |
| Nextcloud | I: the PDF and Postscript preview providers are not in the default list of enabled providers. An admin must switch them on. No Nextcloud statement found | Providers enabled | HIGH |
| Paperless-ngx | I: the official Dockerfile installs the distro ghostscript and the parser uses ocrmypdf. R: an email attachment through a configured inbox reaches Ghostscript for PDF/A conversion (source-mapped, not executed). No project statement | A configured mail inbox | HIGH (inferred) |
| Other researcher-tested apps | R only: DokuWiki with its optional ImageMagick backend on an open wiki, Mayan EDMS 4.11.5 (external email to a configured POP3 source), ResourceSpace 11.0 (authenticated upload or upload share), and Plesk Obsidian 18.0.79 with Roundcube 1.6.17 (an AppArmor profile blocked the shell in an enforced test, the live endpoint was not tested) | Per application | Depends on login |
| Google | R only: the researcher says a signed-out request reached Ghostscript 10.05.0 in a Google production service, with a bounded file read as proof, and that the service mitigated the affected path on 10 November 2026. The Hacker News reports the same. No Google statement found in our sources | Not applicable to your hosts. Never read this as Google being breached | Not rated |

- Precondition for every row (inferred from the CVE and Ghostscript's role): an untrusted PostScript, EPS or PDF file reaches Ghostscript on a host or image that runs a version before 10.08.0, or a build without the distro backport.
- Hosts without Ghostscript have no path. Pillow and Nextcloud work without it but lose EPS or PDF previews (our reading).
- Every R row is the researcher's own testing, not ours. Each per-application exploit is marked "Not published" by the researcher, and what is public is a memory-write step, not a full command-execution chain. Debian 13 is the only distro the researcher tested.
- The researcher's 25 September teaser listed many named companies as reached by one flaw (a claim, not confirmed for any of them). The researcher and The Hacker News say reports for Dropbox and other unnamed services are separate Ghostscript bugs, not this CVE, and WordPress core needs a login. No named company is confirmed compromised.
- Containers: per the researcher and The Hacker News, a container image or bundled app with its own Ghostscript stays vulnerable after the host updates. No official Ghostscript image exists, and images inherit distro packages (inferred).

*Sources: the researcher's write-up, The Hacker News, the WordPress advisory for CVE-2026-65640, the Roundcube advisory and source, Pillow's EPS plugin source, ImageMagick delegate and coder source files, cups-filters source, MediaWiki PdfHandler files, the Nextcloud configuration sample, the Paperless-ngx Dockerfile and parser*

---

## ATTACK TIMELINE

### From the fix to the disclosure

The fix came first and the news came about nine to eleven weeks later. That gap matters more than any single date below. Times are UTC. Where a date comes from the researcher, the table says so.

| When (UTC) | What happened |
| --- | --- |
| 12 August 2026 | WordPress releases 7.0.4 with its own fix, CVE-2026-65640 (date from the researcher and The Hacker News, both third party). The CVE record for that bug was published on 17 August at 20:55 |
| 2 September 2026, 11:04 | Ken Sharp of Artifex commits the fix (stamped 12:04:15 +0100). The CVE record's public date is also 2 September. The exact time the commit became public is not verified |
| 8 September 2026 | Ghostscript 10.08.0 is released. The release notes say it "addresses a number of potential security issues" and name no CVE |
| 25 September 2026 | The researcher posts a short public teaser that lists targets (claims, covered in the exposure part of this analysis) |
| 19 October 2026 | Roundcube posts its 1.6.20 and 1.7.5 news item (image handling hardening). Its GitHub advisory follows on 22 October at 03:33 |
| 21 October 2026 | Ubuntu publishes USN-8949-1, "Ghostscript vulnerabilities". The researcher says it covers this bug. Ubuntu's own CVE page does not say so |
| 9 November 2026, 22:03 | CVE-2026-125396 is reserved |
| 9 November 2026, 23:28 | The CVE record is published, with VulnCheck as the CNA |
| 10 November 2026 | NVD publishes at 00:17. CISA adds its SSVC entry at 16:29. The Ubuntu CVE page gives 10 November as its publication date. The researcher says one large production service mitigated its affected path on this date (researcher-stated, not confirmed by that service) |
| 18 November 2026 | Ubuntu's CVE page is last updated. The researcher's application index shows "Updated 18 November 2026" |
| 21 November 2026 | The researcher's write-up carries this date on its byline (no time shown). The oss-security announcement is listed under the same day |
| 22 November 2026, 04:06 | The CVE record is updated with added references |
| 22 November 2026, 05:18 | NVD records its last modification |
| 22 November 2026 | The Hacker News publishes its article (no time shown) |

*Sources: Ghostscript release notes, the Artifex fix commit, the CVE record, NVD, the CISA entry in the CVE record, Ubuntu CVE page and USN-8949-1, the Roundcube advisory, the WordPress advisory and CVE record, the researcher's write-up, The Hacker News*

### Why the news is the disclosure and not a new patch

The patch has been public since early September. What arrived in November was the CVE number, the score and the researcher's write-up. Anyone who waited for a CVE before patching started late. Jan Schaumann, replying on oss-security (a third party opinion), put the date reasoning like this: "If GS published a fix on 2026-09-08, then we should assume that this vulnerability was public as of that date."

One link in the table is weaker than the rest. The Ubuntu link to this CVE is the researcher's statement, since Ubuntu's CVE page still lists every release as "Needs evaluation" and its notice page, as saved, shows only two CVE numbers.

*Sources: the oss-security thread, the researcher's write-up, Debian security tracker, Ubuntu CVE page and USN-8949-1*

### Which day the oss-security announcement landed

Early notes disagreed on whether the oss-security announcement was posted on 21 or 22 November. The day index for 21 November lists it as message 2, titled "Ghostscript 10.08.0 fixes multiple CVEs, including "upload2shell"", posted by Alan Coopersmith. So the announcement is dated 21 November. The reply by Jan Schaumann carries the header "Date: Sat, 21 Nov 2026 14:59:00 -0500" (19:59 UTC on 21 November), but the archive files it under 22 November as message 1. That is the page the CVE record links.

We did not save the announcement page itself. Its text is known only from two lines quoted in the reply: "Ghostscript 10.08.0 was released on 2026-09-08" and "identifying CVE-2026-125396 as also fixed in this release, and detailing ways it was found to be exploitable through other programs passing files to Ghostscript."

*Sources: oss-security day index for 21 November and the reply archived on 22 November*

---

## AM I AFFECTED? SELF-ASSESSMENT

The checks below are manual and read-only. Run the host commands as root where a comment says so, or they may miss files and processes you cannot read. We did not run these commands ourselves: gs, magick and convert are not installed on the research machine. Syntax was checked against saved documentation where noted.

Two things shape every answer here. First, Upload2Shell is about Ghostscript, but the risk comes from whatever hands a file to it. Second, a Ghostscript version number can mislead: distro builds keep old numbers after a backport, and a container image carries its own copy.

### Quick 3-minute assessment

**STEP 1: Which hosts and images have Ghostscript? (1 minute)**

```bash
# Ghostscript version on this host (prints the version number)
gs --version

# Running processes that use Ghostscript or an image converter (run as root)
ps -eo user,pid,cmd | grep -E '[g]s |[m]agick|[c]onvert'
```

Inside a container, repeat the check from the inside, because each image carries its own copy:

```bash
# Ghostscript version inside a running container (replace <container> with its name or ID, run as root)
docker exec <container> sh -c 'gs --version'

# Same check for an image that is not running (inferred from the per-distro commands, not run)
docker run --rm --entrypoint sh <image> -c 'gs --version; dpkg -s ghostscript 2>/dev/null || rpm -q ghostscript 2>/dev/null || apk info -v | grep ghostscript'
```

On Kubernetes, list the pods first, then run the container check against each one that handles documents:

```bash
# Every pod in every namespace, so you can pick the ones that convert uploads or print
kubectl get pods -A
```

Inventories miss some places, so look there too: forgotten virtual machines, cloud images, test and staging servers, and container images built on a distro base that installs Ghostscript as a dependency. Hosts with no Ghostscript have no path to this bug, and Pillow and Nextcloud keep working without it but lose EPS or PDF previews (our reading).

*Sources: Pillow source, the researcher's write-up, The Hacker News, our reading of the per-distro package commands (checked on 22 November 2026)*

---

**STEP 2: Does this build carry the fix? (1 minute)**

Start with the version traps. The upstream fix is in Ghostscript 10.08.0 (8 September 2026). The CVE record says "before 10.08.0" and gives no start version, so we cannot tell you the first vulnerable release. Older release lines get no upstream backport that we saw. They are fixed only by distro backports, and those keep the old number (inferred). So "gs --version shows 10.05.1" does not mean vulnerable on Debian.

```bash
# Ghostscript version (all platforms)
gs --version
# Debian and Ubuntu: installed package and the version your repositories offer
dpkg -s ghostscript
dpkg -l 'libgs*'
apt-cache policy ghostscript
# RHEL family and SUSE: installed package version
rpm -q ghostscript
# Alpine: installed package version
apk info -v | grep ghostscript
# Homebrew: installed version
brew list --versions ghostscript
```

**Interpretation:**

- Upstream builds (source builds, Arch, Homebrew, Debian forky and sid): the Ghostscript version decides. 10.08.0 or later is fixed. Arch (extra, 10.08.0-1), Homebrew (stable 10.08.0), Debian forky and sid (10.08.0~dfsg-2) and Alpine edge (10.08.0-r0) carry it. Arch, Homebrew and Alpine edge are inferred fixed, since they are upstream code. The Debian tracker marks forky and sid fixed.
- Debian 13 trixie: 10.05.1~dfsg-1+deb13u2 or later is fixed (DSA-6516-1). The tracker marks deb13u3 as fixed.
- Debian 12 bookworm: fixed only in the security repository, at 10.0.0~dfsg-11+deb12u9 or later (DLA-4914-1, Debian LTS). The release pocket version deb12u8 is still marked vulnerable. A machine without the bookworm-security repository stays on deb12u8.
- Ubuntu: not confirmed fixed. Ubuntu's CVE page says "Needs evaluation" on all seven releases. USN-8949-1 of 21 October lists fixed package versions that the researcher says cover this bug (researcher-stated, unconfirmed by Ubuntu). For comparison: 26.10 10.07.1~dfsg-1ubuntu2.1, 26.04 10.06.0~dfsg-3ubuntu1.2, 24.04 10.02.1~dfsg1-0ubuntu7.10, 22.04 9.55.0~dfsg1-0ubuntu5.15, 20.04 9.50~dfsg-5ubuntu4.15+esm3 (Ubuntu Pro), 18.04 9.26~dfsg+0-0ubuntu0.18.04.18+esm6 (Ubuntu Pro), 16.04 9.26~dfsg+0-0ubuntu0.16.04.14+esm11 (Ubuntu Pro). These versions belong to the notice and are not confirmed for this CVE.
- Red Hat family: no Red Hat statement at the cut-off. The security data API returned "Not Found" for this CVE. The researcher did not establish whether current Red Hat, Rocky Linux, AlmaLinux, Oracle Linux or stable Fedora packages carry the fix (The Hacker News, third party).
- SUSE: mostly open. The page shows rows as "In progress" and "Affected", none "Resolved", and no SUSE-SU advisory was seen. openSUSE Tumbleweed lists a released fix, ghostscript 10.08.0-5.1 or later. SUSE Linux Enterprise builds are listed as "in QA", not released.
- Amazon Linux: AL2, AL2023 and the AL2027 preview ghostscript show "Pending Fix". Two AL2 font packages show "Not Affected".
- Alpine stable branches: the newest Ghostscript fix in the security database is 10.05.1-r0, and the database has no mapping for this CVE. Only edge is inferred fixed.

*Sources: Artifex release notes, Debian security tracker, DSA-6516-1 and DLA-4914-1, Ubuntu CVE page and USN-8949-1, Red Hat security data, SUSE and Amazon Linux CVE pages, Alpine, Arch and Homebrew package data, The Hacker News (checked on 22 November 2026)*

---

**STEP 3: Which applications hand files to Ghostscript? (1 minute)**

An affected Ghostscript is only the first half. The second half is an untrusted PostScript, EPS or PDF file reaching it (inferred from the CVE and from Ghostscript's role). The researcher says files may carry an image extension and still reach Ghostscript. The commands below find the paths.

#### ImageMagick: formats and policy

ImageMagick sends PostScript, EPS and PDF to Ghostscript, and it reads the first bytes of a file, so the extension is only a hint (inferred from its source). Check what it will accept and whether a policy blocks it.

```bash
# ImageMagick 7: version, then the format list (look at EPS, PS, PS2, PS3, PDF and XPS and their r/w flags)
magick -version
magick -list format
# ImageMagick 6: the same checks
convert -version
convert -list format
# Policy that ImageMagick loads (version 7). Expect delegate "*" with rights none if a stopgap is in place
magick identify -list policy
# Policy on ImageMagick 6 (our reading, not in the ImageMagick documentation we checked)
identify -list policy
# The Ghostscript command lines ImageMagick would run
magick -list delegate
convert -list delegate
```

The policy listing prints the path of each policy file it loads (our reading), so you can tell which file counts.

#### CUPS sharing

```bash
# Current CUPS settings, one name=value per line. This changes nothing. Look at _share_printers and _remote_any (run as root)
cupsctl
# The queues this server offers
lpstat -v
# Is cupsd listening on a network port? (run as root)
ss -tlnp
```

A shared queue that accepts jobs without authentication from an untrusted network is the setting that matters. The researcher reports a command run as the lp account from an anonymous print job on Debian 13, the only distro tested (third party).

#### WordPress and Roundcube

```bash
# WordPress version (replace <wordpress-root> with your install folder)
grep -E '^.wp_version =' <wordpress-root>/wp-includes/version.php
# Is ImageMagick and Ghostscript on the web host? (Debian and Ubuntu)
dpkg -l | grep -E 'imagemagick|imagick|ghostscript'
# Is Ghostscript on the web host? (RHEL family)
rpm -qa | grep -E 'ImageMagick|imagick|ghostscript'
# Version of each public upload plugin the researcher names. A "No such file" error means that plugin is not installed at that path
grep -m1 'Version:' <wordpress-root>/wp-content/plugins/forminator/forminator.php
grep -m1 'Version:' <wordpress-root>/wp-content/plugins/essential-addons-for-elementor-lite/essential_adons_elementor.php
# Roundcube version (replace <roundcube-root> with your install folder)
grep -n RCMAIL_VERSION <roundcube-root>/program/include/iniset.php
```

WordPress core needs a login: WordPress's own advisory gives the condition as an Author level user or higher, with the upload_files capability, plus Imagick and Ghostscript on the server. WordPress 7.0.4 and 6.9.7 carry that fix, and it covers a different point in the chain, so updating one does not remove the need for the other (The Hacker News, third party). The two plugin paths are researcher-only claims against a signed-out form, and no source we checked gives a fixed plugin version. Roundcube before 1.6.20 or 1.7.5, with ImageMagick present, is the path the researcher links to this chain, but the Roundcube advisory does not name Ghostscript or this CVE.

#### MediaWiki PdfHandler

```bash
# Is PdfHandler loaded? (our reading: a wiki can also load it another way, and the wiki's Special:Version page lists installed extensions)
grep -n PdfHandler <wiki-root>/LocalSettings.php
# Where does the wiki call Ghostscript? Look for a path to gs (adjust the path)
grep -rn 'bin/gs' <wiki-root>/extensions/PdfHandler/extension.json
```

Any wiki with PdfHandler enabled and uploads permitted calls gs for PDF thumbnails with -dSAFER (inferred from the extension's configuration). The researcher reports a reproduction on a wiki set up for anonymous PDF uploads. We found no Wikimedia statement.

#### Pillow

```bash
# Python code that opens images from users (adjust the path to your app)
grep -rn 'Image.open' /srv/app --include=*.py
# Code that already limits the formats Pillow tries
grep -rn 'formats=' /srv/app --include=*.py
```

Pillow's EPS plugin is on by default, goes by file content and not by extension, and calls gs only when the app loads the image and the gs program is installed (from the Pillow source). An app that passes a short list of formats to Image.open() never tries EPS. The researcher traces more Python web apps from their code, mostly without running them.

#### Nextcloud preview providers

```bash
# Which preview providers are enabled? If nothing is listed, the defaults apply (adjust the path)
grep -n -A 20 enabledPreviewProviders <nextcloud-root>/config/config.php
```

The PDF and PostScript providers (OC\Preview\PDF and OC\Preview\Postscript) are not in the default list, so an admin has to switch them on (inferred from the Nextcloud sample config). We found no Nextcloud statement on this bug.

#### Paperless-ngx

```bash
# Ghostscript inside the Paperless container (replace <container> with its name or ID, run as root)
docker exec <container> sh -c 'gs --version'
docker exec <container> dpkg -s ghostscript
```

The official Dockerfile installs the distro Ghostscript package, and the parser uses ocrmypdf (inferred). The researcher says an email attachment through a configured inbox reaches Ghostscript for PDF/A conversion, from reading the code and not by running it. No project statement was found.

*Sources: ImageMagick documentation and delegate list, CUPS man pages, WordPress advisory, Roundcube advisory, MediaWiki PdfHandler configuration, Pillow source and docs, Nextcloud sample config, Paperless-ngx Dockerfile and parser, the researcher's write-up, The Hacker News (checked on 22 November 2026)*

---

**STEP 4: Is a stale copy still running? (30 seconds)**

A Ghostscript started fresh for each job picks up a new package on the next job. A long-running process that loads the Ghostscript library keeps the old copy in memory until it restarts (inferred, our reading).

```bash
# Processes that still hold a replaced copy of the Ghostscript library. Each line printed is /proc/<pid>/maps for one such process (Linux, run as root)
grep -l 'libgs.*(deleted)' /proc/[0-9]*/maps 2>/dev/null
```

An ImageMagick built against the Ghostscript library inside PHP-FPM is the usual example.

*Sources: our reading of standard /proc usage and of how Ghostscript is started (checked on 22 November 2026)*

---

### Full exposure checklist

**You are VULNERABLE if ALL of these are true:**

- [ ] A Ghostscript before 10.08.0 runs on the host or in an image, and it is not a distro build that carries the backport (Debian 13 needs deb13u2 or later, Debian 12 needs deb12u9 or later from the security repository, and nothing is confirmed for Ubuntu)
- [ ] An untrusted PostScript, EPS or PDF file can reach it, directly or through ImageMagick, GraphicsMagick, Pillow, libvips, Qt image plugins or a document pipeline. The extension does not matter
- [ ] The path is not blocked by a delegate policy, a removed Ghostscript package or a locked-down account with no shell

**Your risk is higher if ANY of these also apply (our reading, tiers are ours and not the CVE's):**

- [ ] CRITICAL tier, our reading: nobody has to log in. That covers a CUPS queue shared with an untrusted network that accepts unauthenticated jobs, Roundcube before 1.6.20 or 1.7.5 with ImageMagick present, WordPress sites with the public-upload plugins the researcher names on a host with Imagick and gs, and any app that passes anonymous uploads or email attachments to ImageMagick, GraphicsMagick, Pillow EPS loading or gs
- [ ] HIGH tier, our reading: the same paths behind a login (WordPress core needs Author or higher), internal document pipelines such as MediaWiki PdfHandler, Paperless-ngx (inferred) and Nextcloud with the PDF or PostScript preview providers enabled
- [ ] The host is Red Hat family, SUSE Linux Enterprise or Amazon Linux, where no fixed package was published at the cut-off
- [ ] The Ghostscript copy lives in a container image or application bundle that nobody updated after the host was patched
- [ ] The account that runs Ghostscript can read credentials, mail or customer files. Command execution as that account (for example lp or www-data, per the researcher) reaches whatever it can read

Our reading explains why these tiers sit above the CVE's own High. The CVSS vectors score Ghostscript as a local file processor (attack vector Local in both). The remote path comes from the application in front of it, and the researcher reports command execution in the setups the researcher tested. The CVE itself stays High (7.8 under CVSS 3.1, 8.5 under CVSS 4.0), never Critical. No attacks were reported at the cut-off.

**LOW tier, our reading:** hosts without Ghostscript, hosts where nothing untrusted reaches it, and fixed builds.

*Sources: the CVE record, the researcher's write-up, The Hacker News, WordPress and Roundcube advisories, Pillow source, Nextcloud sample config, our reading (checked on 22 November 2026)*

---

### You are SAFE if:

- [ ] Every Ghostscript you run is 10.08.0 or later, or a distro build at or above the distro's fixed build (judged by the distro tracker, not by the upstream number)
- [ ] Every container image and application bundle that carries its own Ghostscript was rebuilt and redeployed, not only the host
- [ ] Long-running services that load the Ghostscript library were restarted after the upgrade (the check in STEP 4 prints nothing)
- [ ] There is no Ghostscript on the host or in the image, so no path exists
- [ ] For hosts you cannot patch yet: untrusted files cannot reach Ghostscript, for example because the ImageMagick delegate and coder policies are in place and confirmed with the policy listing, CUPS queues are not shared with untrusted networks, and apps that open untrusted images pass only the formats they need. These are stopgaps, not a fix
- [ ] Applications with their own fixes are updated as well: WordPress 7.0.4 or 6.9.7, Roundcube 1.6.20 or 1.7.5. Each closes one route and not the Ghostscript bug

**IMPORTANT:** The -dSAFER switch does not protect you here. The bug gets around it. Ghostscript has had SAFER on by default since 9.50, every ImageMagick delegate line that starts Ghostscript and the Pillow EPS plugin already pass -dSAFER, and all of them are still in scope. Do not rely on -dSAFER, and do not turn it off either: Artifex warns that with -dNOSAFER or -dDELAYSAFER, PostScript programs can read, write, rename or delete any file the operating system lets the account touch. Artifex gives no workaround for this bug in the pages we saved.

A clean version check on the host proves little if an image carries its own copy. Absence of attack signs proves little too, because we found no public indicators. Check each host, image and application with the commands above.

*Sources: Ghostscript usage documentation, ImageMagick delegate file, Pillow EPS plugin source, Artifex, distro trackers, the researcher's write-up, The Hacker News (checked on 22 November 2026)*

---

## PROTECTION ROADMAP

### For non-technical executives

#### HOUR 1: Find where documents meet Ghostscript

**Immediate actions checklist:**

- [ ] Get IT, the engineering leads and your hosting and software providers on one call
- [ ] Ask: "Which of our systems take files or email from outside and convert, preview or print them?" Think of contact forms, mail systems, wikis, document and file-sharing platforms, print servers and anything a hosting company, agency or vendor runs for you
- [ ] Ask for two facts per system: whether Ghostscript is installed, and which version or distro build it is. IT runs the Quick 3-minute assessment. A patched package does nothing until the service that uses it restarts
- [ ] Ask every vendor whose product bundles its own copy, in writing, whether it carries the fix. A patched host does not patch a copy inside a container image or an application
- [ ] Flag any system where a stranger can send a file with no login: shared print queues, public upload forms, inbound mail. Our reading rates those CRITICAL, and the CVE itself is rated High
- [ ] Approve emergency maintenance, including restarts during business hours
- [ ] Tell legal, compliance and your cyber insurer that you are responding

**Decision points:**

- Everything fixed and restarted: document it and move to WEEK 1: Confirm with evidence.
- Open systems on a platform that has shipped a fix: approve patching and a restart today.
- Open systems on a platform with no fixed package yet (Red Hat family, SUSE Linux Enterprise, Amazon Linux at the cut-off, and Ubuntu until it confirms): approve the stopgaps in For technical teams and ask the vendor in writing for a date.
- Systems that are behind a login or internal only: patch in the next scheduled window, sooner if they handle files from outside.

---

#### DAY 1: Decide what happens to systems that cannot be patched today

**Executive decision checklist:**

- [ ] Approve maintenance windows. Services that convert documents may restart, and container setups have to be rebuilt and redeployed, so plan for short interruptions
- [ ] Decide what to do about systems that cannot take the fix today:
    - [ ] **Option A:** Move the service to a platform or build that already has the fix (safest)
    - [ ] **Option B:** Close the exposed entry point until the fix arrives: stop sharing print queues with outside networks, or turn off public file uploads and mail previews
    - [ ] **Option C:** Switch off document and PDF conversion for outside files. This costs features such as previews and thumbnails, and it is a stopgap and not a fix
    - [ ] **Option D:** Run conversion under a locked-down account or container with no network and no shell (the researcher and The Hacker News both describe this kind of containment limiting damage in one test). It limits damage, it does not replace patching
- [ ] Communication plan:
    - [ ] Brief the board if you are publicly traded
    - [ ] Prepare a customer notice in case a service has to go offline
    - [ ] Tell your cyber insurer
    - [ ] Ask legal for a compliance read
- [ ] Resources:
    - [ ] Approve overtime or outside help if the team is stretched
    - [ ] Call in your incident response retainer if you have one

---

#### WEEK 1: Confirm with evidence

**Follow-up checklist:**

- [ ] Confirm, with evidence, that every system that takes outside files runs a fixed build and has restarted its converting services. Evidence means output from the system, not a ticket
- [ ] Ask who owns each container image and application bundle, and have each owner confirm its own copy of Ghostscript
- [ ] Re-check vendor advisories. At the cut-off Red Hat had no record of this CVE, SUSE showed mostly "In progress" and "Affected" rows, Amazon Linux showed "Pending Fix", and Ubuntu's CVE page still said "Needs evaluation"
- [ ] Look back through logs to the first fix date, 2 September 2026, for odd activity around upload and mail systems. No attacks were reported at the cut-off, but we found no public indicators, so clean logs prove little
- [ ] Rotate credentials that a document-handling account could read, on any system that showed suspicious activity
- [ ] Hold a post-incident review with the technical teams
- [ ] Compliance:
    - [ ] Check notification duties if you found any sign of compromise
    - [ ] Keep timestamped records of everything you did
    - [ ] Preserve evidence
    - [ ] Get legal advice before you conclude "no breach"

---

#### MONTH 1: Make document handling safer for good

**Lasting improvements:**

- [ ] Keep a live inventory of every system that converts, previews or prints documents, with the Ghostscript copy it uses, who supplies it and whether outside people can send it files
- [ ] Decide on purpose which systems should accept PostScript, EPS and PDF from strangers at all, and turn conversion off where nobody needs it
- [ ] Put document conversion in a contained environment with no network and no shell, as a layer that limits damage
- [ ] Follow the security notices of your distro and your software vendors, not only CVE feeds. This fix was public for about nine weeks before the CVE appeared, and the release notes named no CVE
- [ ] Agree a patch and restart policy: how fast a fix reaches production, who may approve an emergency restart, and who owns the images that carry their own copy
- [ ] Check what your scanner sees: does it know distro backports and bundled copies, or only version numbers?
- [ ] Review hosting and software contracts for patch timelines and notification duties
- [ ] Run a tabletop exercise based on a malicious file arriving by email or upload

*Sources: Artifex and the Ghostscript project, the CVE record, distro and vendor advisories, the researcher's write-up, The Hacker News, WordPress and Roundcube advisories, CUPS man pages, Pillow documentation (checked on 22 November 2026)*

---

### For technical teams

The bug is High on paper (CVSS 3.1: 7.8; CVSS 4.0: 8.5, both from the CVE record) and the fix is Ghostscript 10.08.0 or your distro's backport. Order your work by exposure, not by score. Our reading, and only ours: a Ghostscript that untrusted people can reach with no login is CRITICAL (CUPS queues shared with untrusted networks, Roundcube before 1.6.20 or 1.7.5 with ImageMagick present, WordPress sites with public upload forms, any app that passes anonymous uploads or mail attachments to ImageMagick, GraphicsMagick, Pillow EPS loading or gs). The same paths behind a login, and internal document pipelines, are HIGH. Hosts with no Ghostscript, hosts where nothing untrusted reaches it, and fixed builds are LOW. The CVE itself is never called Critical.

#### IMMEDIATE ACTIONS FOR GHOSTSCRIPT HOSTS (Hour 1-2)

**Phase 1: Assessment and inventory**

**Checklist:**

- [ ] Find every host and image that has Ghostscript: servers, virtual machines, container images and running containers, print servers, mail servers, wikis, document and OCR pipelines, and the golden images that new servers start from
- [ ] Record the Ghostscript version, the package build and who supplies it (a distro, a vendor, or you, from source)
- [ ] Record every program that can call it: ImageMagick (convert or Imagick inside PHP), GraphicsMagick, Pillow with EPS loading, libvips, Qt image plugins, CUPS filters, MediaWiki PdfHandler, OCR tools
- [ ] Record where untrusted files come from: public upload forms, inbound mail attachments, anonymous print jobs, shared queues, user avatars and contact photos
- [ ] Record any copy of Ghostscript bundled inside an application or image. The researcher and The Hacker News both say updating the host package does not update a bundled copy
- [ ] Put hosts that take untrusted input with no login first, then hosts that take it behind a login, then internal pipelines, then hosts nothing untrusted reaches (our reading)

**Commands for assessment:**

Every command here only reads. Commands marked "run as root" need it. We ran none of them: gs, magick and convert are not installed on the research machine, so syntax is checked against saved documentation where noted.

```bash
# Which distribution and release is this host?
cat /etc/os-release

# Ghostscript version (prints the version, or an error if gs is not installed)
gs --version
# Debian and Ubuntu: installed Ghostscript packages and their versions
dpkg -s ghostscript
dpkg -l 'libgs*'
# RPM distros (RHEL family, SUSE, Amazon Linux)
rpm -q ghostscript
# Alpine
apk info -v | grep ghostscript
# Homebrew
brew list --versions ghostscript

# ImageMagick 7: version, active policy, enabled formats, delegate command lines
magick -version
magick identify -list policy
magick -list format
magick -list delegate
# ImageMagick 6
convert -version
identify -list policy
convert -list format
convert -list delegate

# CUPS: current settings, one name=value per line, no changes. Look at _share_printers and _remote_any
cupsctl
# CUPS: the queues
lpstat -v

# Container image: Ghostscript version and package, from a throwaway container
docker run --rm --entrypoint sh <image> -c 'gs --version; dpkg -s ghostscript 2>/dev/null || rpm -q ghostscript 2>/dev/null || apk info -v | grep ghostscript'
# Running container: Ghostscript version
docker exec <container> sh -c 'gs --version'
# Which image a local image is built from, and its layers
docker image inspect <image>
# Kubernetes: pods and the nodes they run on
kubectl get pods --all-namespaces -o wide
```

How to read the output:

- `gs --version` prints the version. Vulnerable means below 10.08.0 and not a distro build that carries the backport. Debian 13 needs 10.05.1~dfsg-1+deb13u2 or later. Debian 12 needs 10.0.0~dfsg-11+deb12u9 or later, from the security repository. Ubuntu has no confirmed fixed version for this CVE (see Option B).
- A distro build keeps its old version number after the backport, so "10.05.1" does not mean vulnerable on Debian 13. Read the package version, not the gs version (inferred from the distro trackers).
- In the ImageMagick format list, look at the rows EPS, PS, PS2, PS3, PDF and XPS and their r and w flags. In the delegate list, look at the gs command lines. What the delegate list prints is inferred, not confirmed in the saved documentation.
- In the policy list, a delegate entry with pattern "*" and rights none means the stopgap in Option B is in place. The list prints the path of each policy file it loads (our reading), so you can see which file counts.
- `cupsctl` with no options changes nothing. A shared queue that accepts jobs from an untrusted network is the CUPS condition the researcher's test used.
- A host with no Ghostscript has no path. Pillow and Nextcloud work without gs but lose EPS or PDF previews (our reading).
- Container images carry their own copy. Check each image separately from the host. For Kubernetes, find the image behind each pod and run the image check on it.
- PHP hosts: check whether Imagick is loaded and whether ImageMagick is built to use the Ghostscript library. A long-running process that loads libgs keeps the old copy in memory until it restarts (inferred, our reading).

Don't test your hosts with proof-of-concept code from public repositories. A search of GitHub at the cut-off found 3 repositories for each of the CVE ID and the name Upload2Shell, all created on 22 November 2026. We did not open them, so what they contain is unknown. The search can undercount. Running unknown code is a common way to get compromised.

**Document your findings:**

```
Host / image / appliance:
Platform and release (/etc/os-release):
Role and exposure [anonymous input / input behind a login / internal only / nothing untrusted reaches it]:
Ghostscript version (gs --version):
Package version (dpkg -s ghostscript, rpm -q ghostscript, apk info -v):
Fixed build for this platform [yes / no / vendor has no fix yet / vendor has not said]:
Programs that call Ghostscript (ImageMagick, GraphicsMagick, Pillow, CUPS, MediaWiki, OCR, other):
Policy in place [delegate "*" none / coder line / none] and the policy file it sits in:
Bundled copy of Ghostscript in an app or image [yes / no], and which:
CUPS queue shared with untrusted networks [yes / no]:
Interim measure, date and who:
Restarted after the upgrade [yes / no, time]:
Status [fixed / exposed / not exposed / no fix yet]:
```

---

**Phase 2: Emergency patching**

**Pre-patch checklist:**

- [ ] Snapshot or back up the host or image, configuration included
- [ ] Note current versions (`gs --version` and the package version) for rollback
- [ ] Write down any interim measure you apply (a policy line, a CUPS setting) so you can undo it on purpose later
- [ ] Tell stakeholders about the maintenance window. Services that load the Ghostscript library need a restart, and a restart cuts jobs in flight
- [ ] Have a rollback plan ready, with a time limit. A rollback puts the vulnerable build back
- [ ] For a host you suspect, capture state before you restart anything, because a restart destroys the memory of the running processes. The detection section says what to look for, and the advanced forensics section says what to preserve

**Patching commands:**

Upgrade Ghostscript to 10.08.0, or install the distro build that carries the fix, then update every container image and application bundle that carries its own copy. Artifex gives no workaround and no sandbox advice for this bug in the pages we saved, so everything under Option B is a stopgap, not a fix.

```bash
# Debian 13 and 12 (Debian 12 needs the bookworm-security repository enabled), Ubuntu 24.04 and later (run as root)
apt-get update
apt-get install --only-upgrade ghostscript libgs10 libgs10-common
# Ubuntu 22.04 and older (run as root). Ubuntu has not confirmed that its builds fix this CVE
apt-get update
apt-get install --only-upgrade ghostscript libgs9 libgs9-common
# Alpine edge only (run as root). Alpine stable branches had no fixed build at the cut-off
apk update
apk upgrade ghostscript
# Arch (run as root). Arch supports full upgrades only
pacman -Syu
# Homebrew
brew upgrade ghostscript
# Docker: rebuild your image so the base image and packages are fetched fresh, then redeploy
docker build --pull --no-cache -t <image> .
# Restart long-running services that load the Ghostscript library, for example PHP-FPM with Imagick (run as root; use your own unit name)
systemctl restart <service>
```

The package names come from the Ubuntu notice USN-8949-1 (libgs10 and libgs10-common on 24.04 and later, libgs9 and libgs9-common on 22.04 and older) and the Debian package tracker. The option `--only-upgrade` upgrades only packages that are already installed and installs nothing new (apt-get manual, our reading). The patch commands are standard package manager usage, our reading.

Red Hat, SUSE Linux Enterprise and Amazon Linux had no fixed package at the cut-off, so this document gives them no upgrade command. Watch the vendor page and use the stopgaps in Option B. Fedora, Rocky, AlmaLinux and Oracle Linux have no command here either: update Ghostscript with the platform's own tooling once a fixed package exists.

These commands cover Debian, Ubuntu, Alpine edge, Arch, Homebrew and Docker. Option A and Option B say what each platform had on 22 November 2026.

**Option A: Platforms with a fixed package (the fix is the package plus a restart of anything that loads it)**

- Upstream and source builds: Ghostscript 10.08.0, released 8 September 2026. Rebuild anything you compile yourself on 10.08.0. No upstream backport was seen for older release lines, so older lines are fixed only by distro backports (inferred).
- Debian 13 trixie: fixed by backport. `ghostscript` 10.05.1~dfsg-1+deb13u3 is marked fixed on the tracker, and the first fixed version is 10.05.1~dfsg-1+deb13u2 (DSA-6516-1). The Debian tracker shows no advisory dates, so we give none.
- Debian 12 bookworm: fixed only in the security repository, at 10.0.0~dfsg-11+deb12u9 (DLA-4914-1, Debian LTS). The release pocket build, 10.0.0~dfsg-11+deb12u8, is still marked vulnerable on the tracker. A machine with the security repository enabled gets deb12u9. The Hacker News lists bookworm as "listed as vulnerable" in the researcher's survey (third party), so check the package version rather than the label.
- Debian forky and sid: fixed in 10.08.0~dfsg-2 (the first fixed version was 10.08.0~dfsg-1).
- Alpine: edge has `ghostscript` 10.08.0-r0 (inferred fixed, because it is upstream code). The Alpine security database has no mapping for this CVE.
- Fedora: rawhide (F46) has 10.08.0-1.fc46 (inferred fixed, no advisory checked). We did not check the stable branches.
- Arch: `ghostscript` 10.08.0-1 in extra, built 8 September 2026 (inferred fixed). Homebrew: stable 10.08.0 (inferred fixed).

**Option B: Platforms with no fix, or no confirmed fix, and the stopgaps**

- Ubuntu: not confirmed fixed. The Ubuntu CVE page shows priority Medium and status "Needs evaluation" on all seven releases (26.10, 26.04 LTS, 24.04 LTS, 22.04 LTS, 20.04 LTS, 18.04 LTS and 16.04 LTS), last updated 18 November 2026. Ubuntu shipped a Ghostscript notice on 21 October (USN-8949-1) that the researcher says covers this bug; Ubuntu's own CVE page does not yet say so. The notice text we saw credits Paulos Yibelo with a font operand check, and its CVE number was cut off in our copy (it is likely this CVE, inferred). The notice lists fixed package versions, which are for the notice and are not confirmed for this CVE: 26.10 10.07.1~dfsg-1ubuntu2.1; 26.04 10.06.0~dfsg-3ubuntu1.2; 24.04 10.02.1~dfsg1-0ubuntu7.10; 22.04 9.55.0~dfsg1-0ubuntu5.15; 20.04 9.50~dfsg-5ubuntu4.15+esm3 (Ubuntu Pro); 18.04 9.26~dfsg+0-0ubuntu0.18.04.18+esm6 (Ubuntu Pro); 16.04 9.26~dfsg+0-0ubuntu0.16.04.14+esm11 (Ubuntu Pro). Install them if you like, and keep the stopgaps in place until Ubuntu says the CVE is fixed.
- Red Hat: no record. At 12:45 UTC on 22 November the Red Hat security data returned "Not Found" for the CVE, and we saw no advisory. The Hacker News says the researcher did not establish whether current Red Hat, Rocky Linux, AlmaLinux, Oracle Linux or stable Fedora packages carry the fix. Say "no Red Hat statement at the cut-off".
- SUSE: mostly open. The product list had 21 rows "In progress" and none "Resolved", with many "Affected" rows (we give no count, because our recount differed from the findings). Examples: "SUSE Linux Enterprise Desktop 15 SP7 ghostscript In progress" and "openSUSE Leap 16.0 ghostscript Affected". We saw no SUSE-SU advisory. SUSE rates the issue important. The release list shows openSUSE Tumbleweed fixed at ghostscript 10.08.0-5.1 or later. SUSE Linux Enterprise 12 SP5 and 15 SP4 to SP7 builds are listed as "in QA", not released.
- Amazon Linux: AL2, AL2023 and AL2027 Preview ghostscript show "Pending Fix". Two AL2 packages, ghostscript-chinese and ghostscript-fonts, show "Not Affected". The Hacker News lists AL2 as "fix pending" in the researcher's survey (third party). Amazon rates it Important.
- Alpine stable branches: v3.22 and older are not fixed in the security database. The newest Ghostscript fix there is 10.05.1-r0.
- ImageMagick and GraphicsMagick: no project statement on this CVE. Nothing is fixed "in ImageMagick". LibreOffice and Nextcloud have no project statement either. LibreOffice exposure is unknown.
- Plugins: no source we checked states a fixed version of Forminator or Essential Addons for Elementor, so this document gives none.
- Vendor state moved while we worked. Re-check before you rely on a "no fix yet" or a "not confirmed".

While you wait for a fix, in order of preference:

1. Where a workload can move, move it to a platform from Option A.
2. Stop untrusted files reaching Ghostscript: switch off the paths in the list below (our reading).
3. Put the converter under a locked-down account, container or profile (containment, below).
4. Check the vendor page every day and patch the day a fixed build appears.

**ImageMagick policy (stopgap).** The ImageMagick project's own policy-secure.xml has this comment and line, exactly:

```xml
<!-- Disable execution of all delegates. -->
<policy domain="delegate" rights="none" pattern="*"/>
```

Its policy-websafe.xml carries the same delegate line under the comment `<!-- Disable all external delegates (Ghostscript, ffmpeg, etc.). -->`. The ImageMagick docs say that starting with ImageMagick 7.0.1-8, external delegates can be globally disabled by setting the pattern to "*".

An older distro bug report on Arch Linux, written for an earlier Ghostscript bug in 2018 and not upstream ImageMagick text, gives a full-disable line for the coders. It adds "This is recommended action for all distros to do." and places it in the ImageMagick 7 policy.xml on Arch:

```xml
<policy domain="coder" rights="none" pattern="{PS,PS2,PS3,EPS,PDF,XPS}" />
```

Our recommended stopgap (our reading): put both lines in the policy.xml that ImageMagick actually loads. The delegate line stops ImageMagick from starting the gs program. The coder line stops it from reading PS, PS2, PS3, EPS, PDF and XPS at all, which also covers builds that use Ghostscript as a library instead of a separate program. Upstream's own coder line, which restricts write for a list that names PS and PDF but not EPS, PS2 or PS3, is not the same thing: our reading is that the delegate line is what stops gs for all of them.

- Case: the ImageMagick docs say glob patterns are case-sensitive before version 7.1.1-16, so coders must be uppercase (for example "EPS") or use case-insensitive patterns.
- ImageMagick 6 ships its policy.xml with a different coder line commented out (rights write, for MVG, PDF, PS, SVG, TXT and XPS), not the stopgap coder line, so add the stopgap coder line on purpose. We could not fetch Debian's own policy file (COULD NOT VERIFY).
- Confirm the result with the policy list from Phase 1 (`magick identify -list policy`; on ImageMagick 6 the equivalent `identify -list policy` is our reading, not in the saved documentation).
- Trade-off (our reading): blocking delegates also breaks PDF and PostScript to image conversion that an app may need. Blocking is not a fix for apps that call gs directly (CUPS, MediaWiki PdfHandler, Paperless-ngx).

**CUPS (stopgap).** Stop sharing queues with untrusted networks, or require authentication, so nobody outside can submit anonymous jobs. The researcher's test on Debian 13 used an anonymous print job to a shared queue and ran a command as the lp user (third party, one remote run plus 20 of 20 local conversions). The cupsctl man page says that with no changes requested it writes the current settings as name=value, one per line, so `cupsctl` alone is read-only. The commands below come from the CUPS man pages (run as root):

```bash
cupsctl --no-share-printers
cupsctl --no-remote-any
lpadmin -p <printer> -o printer-is-shared=false
```

The man page says `--no-share-printers` disables "sharing of local printers with other computers", `--no-remote-any` disables "printing from any address, e.g., the Internet", and `printer-is-shared=false` sets the destination to unshared. Trade-off (our reading): computers that print through this server stop working until you let them back in a narrower way. Requiring authentication on job submission is set through cupsd.conf policies. For the syntax, see the CUPS documentation. The Hacker News says exposure can be reduced by requiring authentication on print queues and by limiting which file types an image processor accepts (third party).

**Pillow (stopgap, in words).** Pillow's own documentation says the formats argument of Image.open() is "A list or tuple of formats to attempt to load the file in. This can be used to restrict the set of formats checked." Our reading: an app that opens untrusted images should pass only the formats it needs, so EPS is never tried, and an app that never needs EPS can leave gs off the host. In the Pillow source we saved, Ghostscript is only called when the image is loaded, and only if the gs binary is present. The EPS plugin looks at content, not the file name, so renaming a file does not matter. This document gives no code for it.

**Containment (third party, then our reading).** The researcher says a policy that stops a renderer from starting a shell can limit damage even after the interpreter is compromised. The Hacker News says an AppArmor profile stopped the compromised interpreter from starting a shell in one test. Our reading: run document conversion under a locked-down account, container or profile with no network and no shell. This is containment, not a substitute for updating.

**Option C: Containers, bundled copies and images**

- A container image or application bundle with its own Ghostscript stays vulnerable after the host updates (the researcher and The Hacker News). Rebuild the image on a base that carries a fixed build, then redeploy. A running container keeps the old code until you replace it, because restarting the old container starts the same old image.
- No official Ghostscript image exists, and images inherit distro packages (inferred). Check the version inside each image, and read the package version, not only the gs version, on Debian and Ubuntu bases.
- EC2 and VM images: update or rebuild the golden image, and every launch template or autoscaling group that points at it. A new instance from an old image comes up vulnerable.
- WordPress and Roundcube: their own fixes (WordPress 7.0.4 and 6.9.7 for CVE-2026-65640, Roundcube 1.6.20 and 1.7.5 for CVE-2026-114727) close one route each. The Roundcube advisory does not name Ghostscript or this CVE, so do not read it as an Upload2Shell fix. The Hacker News says the WordPress fix and the Ghostscript fix cover different points in the same chain, so updating one does not remove the need for the other. WordPress core needs a login (Author, or a Contributor granted upload_files). The plugin routes the researcher names do not.

**Not mitigations:**

- -dSAFER. It is the thing the bug gets around. Ghostscript has had it on by default since 9.50, every ImageMagick delegate line that starts Ghostscript and the Pillow EPS plugin already pass it, and all of them are still in scope. Do not suggest it. Do not suggest -dNOSAFER or -dDELAYSAFER either. Artifex says that if Ghostscript is started with them, "PostScript programs are allowed to read, write, rename or delete any files in the system that are not protected by operating system permissions."
- Updating only the host when the app bundles its own copy.
- The WordPress or Roundcube application fixes alone.
- Waiting for KEV or a high EPSS score. The CVE is not in KEV at the cut-off, and EPSS is 0.00164 (0.16 percent, percentile 0.056, 21 November 2026). EPSS is a one-day-old model score, not evidence of safety.

**Restart into the fixed build (the step people skip)**

A gs started fresh for each job picks up the new package on the next job. A long-running process that loads libgs, for example ImageMagick built with the Ghostscript library inside PHP-FPM, keeps the old copy in memory until that process restarts (inferred, our reading). Restart those services after the upgrade. The restart command is in the patching block above. In a container, rebuild and replace it.

**Verification:**

```bash
# Ghostscript version. Compare it with the fixed versions in Option A
gs --version
# Debian and Ubuntu: installed package version
dpkg -s ghostscript
dpkg -l 'libgs*'
# RPM distros
rpm -q ghostscript
# Alpine
apk info -v | grep ghostscript
# Homebrew
brew list --versions ghostscript
# Processes that still hold a replaced copy of the Ghostscript library after an upgrade (Linux, run as root). Each line printed is /proc/<pid>/maps for one such process
grep -l 'libgs.*(deleted)' /proc/[0-9]*/maps 2>/dev/null
# Container: Ghostscript version inside the rebuilt image
docker exec <container> sh -c 'gs --version'
```

- Upstream builds: `gs --version` must show 10.08.0 or later.
- Distro builds: the package version must match or beat the fixed version in Option A. Debian 13 needs 10.05.1~dfsg-1+deb13u2 or later, and Debian 12 needs 10.0.0~dfsg-11+deb12u9 or later from the security repository. For Ubuntu, nothing is confirmed, so the package version alone does not close the item.
- The libgs check lists processes whose Ghostscript library was replaced on disk while they kept running. Any line printed is a process to restart. The command is standard /proc usage (our reading). No line printed means no such process was found, not that nothing loads the library elsewhere.
- Containers: confirm the running container was created from the rebuilt image, and run the version check in it.
- After the stopgaps, run the policy list and the CUPS settings check again and keep the output.

**Post-patch checklist:**

- [ ] Every patched host shows the fixed build in the version checks, and no process still holds the old library
- [ ] Conversions, thumbnails, print jobs and mail previews work after the restart
- [ ] Decide on purpose what stays of the interim measures. A patch does not remove a policy line or a CUPS setting. Keep them as long as you want, or remove them with the fixed build running
- [ ] Rebuild the images and launch templates so that new hosts don't come back on the old build
- [ ] Update every bundled copy, not just the host package
- [ ] If a scanner still flags a patched host, check the version number trap before you open a ticket: a distro package can carry the fix under an older upstream number
- [ ] Keep the version output as evidence
- [ ] Update your asset inventory and record the restart time
- [ ] On hosts still waiting for a fix, keep the policy and CUPS stopgaps and watch the vendor page

*Sources: Artifex Ghostscript release notes and usage documentation, the CVE record, Debian security tracker and advisories DSA-6516-1 and DLA-4914-1, Ubuntu CVE page and USN-8949-1, Red Hat security data, SUSE, Amazon Linux and Alpine security data, Fedora, Arch and Homebrew package data, the WordPress and Roundcube advisories, ImageMagick security policy documentation and upstream policy files, an Arch Linux bug report, CUPS man pages, Pillow documentation, the researcher's write-up (third party), The Hacker News (third party), GitHub repository search count (state on 22 November 2026, 12:30 UTC)*

---

#### DETECTION & HUNTING FOR GHOSTSCRIPT ABUSE (Day 2-3)

No source we relied on lists indicators of compromise: no file hashes, address lists, log patterns or request signatures. Artifex, the CVE record and the researcher publish no exploit signature. What exists is the stated impact (command execution as the account running Ghostscript) and the process and file signals that any such compromise leaves. That leaves you looking for behaviour: hosts that still run the bug, Ghostscript running where it should not, commands started under it, and files whose content does not match their name. We have no source that says what a successful attempt leaves in the logs, so a clean result proves little.

Sources disagree little on how far the public work has got. The researcher's write-up shows a memory-write step, not a full command-execution chain, and the researcher marks each per-application exploit "Not published". The Hacker News agrees, and says the public proof fails before that point on the patched 10.08.0 build. No attacks are reported at the cut-off (see the review window under advanced forensics). Plan on the basis that a full chain may exist privately.

Inventory comes first, because a signal from a host you can't place can't be read. Every command here only reads. Commands marked "run as root" need it.

**Check for signs of attempts and compromise**

**Fleet inventory at scale:**

Ask three questions of every host. Which Ghostscript build is installed? Which program can pass it an untrusted file? Is the running process on the fixed library? Run the Phase 1 commands through your configuration management, remote execution or EDR tooling and collect the output into one table keyed by host. A package list says what is installed, and this bug is fixed only in the process that is running.

| What you see | Reading | Next step |
| --- | --- | --- |
| Upstream gs below 10.08.0, an untrusted-input path, no policy block | Exposed to this bug | Patch and restart, anonymous-input hosts first. Apply the stopgaps until then |
| Upstream gs below 10.08.0, ImageMagick with the delegate line set to none, and no app that calls gs directly | Reduced exposure. The route through ImageMagick is closed, and a policy is not a fix | Patch in the normal window, soon |
| gs below 10.08.0 on a host where CUPS, MediaWiki PdfHandler or Paperless-ngx call gs directly | A delegate policy does not cover these | Patch. For CUPS, unshare the queue until then |
| Debian or Ubuntu package with an older-looking number | Not evidence either way, because distro packages keep the old number after a backport | Compare the package version with the distro advisory (Option A and Option B) |
| Debian 12 with deb12u8 | Marked vulnerable on the tracker. The security repository has deb12u9 | Enable the security repository and upgrade |
| Ubuntu, any release | No fix confirmed for this CVE | Keep the stopgaps. Re-check the Ubuntu CVE page |
| Red Hat family, SUSE Linux Enterprise or Amazon Linux | No fixed package at the cut-off | Keep the stopgaps. Watch the vendor page |
| Container image with its own gs | The host patch does not touch it | Rebuild the image and redeploy |
| Fixed package installed, but a process still holds the deleted library | The fix is on disk and the old code still runs | Restart that process |
| No gs installed | No path | None for this bug. Other Ghostscript bugs fixed in 10.08.0 are a reason to patch anyway |

Containers carry their own Ghostscript. A scan of the host doesn't see inside them, so list the running containers with your runtime and run the container commands for each one.

*Sources: the CVE record, Debian, Ubuntu, Red Hat, SUSE and Amazon Linux trackers, ImageMagick delegate and policy files, Pillow source, the researcher's write-up (third party), The Hacker News (third party) (state on 22 November 2026)*

**Hunting ideas (all our reading):**

Expect false positives, and treat every hit as a lead.

- gs processes running as web or print users (for example lp, www-data, the Roundcube account), especially long-running ones or ones with odd parents.
- A shell (sh, bash, dash) or other unexpected child process under gs or under a converter that calls gs. Command execution as the account running Ghostscript is the stated impact.
- Uploaded or attached files whose content type is PostScript, EPS or PDF behind an image extension. The researcher says the files carry trusted extensions such as .png and .jpg (third party). Content decides how ImageMagick and Pillow treat a file, so the name proves nothing.
- The CUPS access log: print jobs from unexpected addresses or with no authenticated user, on queues that are shared. We give no log paths or field names, because no source we checked states them.
- Web server and mail logs: first look at upload endpoints on WordPress sites with Forminator or Essential Addons public forms, and at inbound mail with PostScript, EPS or PDF attachments to Roundcube hosts.

```bash
# Processes running as web or print users, with their parents
ps -eo user,pid,ppid,lstart,args | grep -E '^(lp|www-data) '
# Ghostscript processes, with their parents and start times
ps -eo user,pid,ppid,lstart,args | grep -E '(^| )gs( |$)'
# The same as a tree, to see what each process started
ps -eo user,pid,ppid,lstart,args --forest
# Listening sockets with their processes (run as root)
ss -tlnp
# Stored uploads whose content is PostScript or PDF. Then look for names ending .png, .jpg or similar
file --mime-type <upload-dir>/* | grep -E 'application/(postscript|pdf)'
# Files in the upload folder newer than the date of the upstream fix
find <upload-dir> -type f -newermt "2026-09-02"
# CUPS service log lines kept by the journal
journalctl -u cups --no-pager
```

Three caveats apply to the process list:

- It shows live processes only. A command that ran and exited leaves nothing for `ps`. Pair it with process-creation logging from your EDR or the audit subsystem, filtered on the accounts that run conversions.
- Normal conversion jobs start gs too. Look at what a gs process started, who started it, and how long it has lived. Baseline a known-good host of the same role first.
- If your conversions run as another user, change the pattern.

For outbound connections, use the tools you already have: firewall or flow logs. We give no command for them, because no source gives a pattern to look for.

A quiet result doesn't clear a host. We found no public indicators, so the absence of these signs does not prove safety. If logs rotate fast or stay only on the host, the evidence may already be gone, so send them off the host (see Monitoring and alerting under the defense-in-depth section).

**How to read the signals together:**

| What you see | Reading | What to do |
| --- | --- | --- |
| An unpatched host that takes untrusted files, and nothing else | Exposed, not known to be hit. Clean logs prove little | Patch and restart. Copy the logs off the host first |
| A PostScript or PDF file behind an image extension in an upload folder | A lead. Some apps store such files on purpose. The researcher says files carry trusted extensions (third party) | Find who uploaded it and when, and check whether the host was patched at the time |
| A gs process owned by the web or print user, long-lived or with an odd parent | A lead | Record the process, its parent and its start time. Compare with a baseline host |
| A shell, download tool or interpreter under gs or a converter, and not in your baseline | Possible command execution as the account running Ghostscript, which is the stated impact | Incident. Preserve first (see the advanced forensics section), then rebuild |
| A new or changed file in a web root, plugin folder or config that you didn't deploy | Possible web shell or persistence | Incident |
| An outbound connection from a converter or gs process to an address you don't know | Possible download or reverse connection | Incident. Block it at your egress point and keep the flow logs |
| Anonymous print jobs on a shared CUPS queue from addresses you don't know | A possible attempt on a host that runs the researcher's tested setup | Unshare the queue, keep the CUPS logs, patch, and run the other checks on this host |

**What the converting account could read:**

The researcher reports command execution as the account running Ghostscript, for example lp on a CUPS server or www-data on a web or mail host (third party). Scope is what that account and that process can read or reach, and that is our reading. Build your rotation list from what the host held:

- Application secrets in web roots and config: database passwords, API tokens, session and signing secrets, `.env` files
- Credentials a mail or web application holds for other systems: mail relays, IMAP and SMTP logins, cloud credentials, backup targets, deploy keys
- Uploaded and stored user files the account could open
- Secrets mounted into the container, where the converter runs in one
- Anything else the account can read

**Compromise indicators checklist:**

- [ ] Every host that takes untrusted files runs a fixed Ghostscript, has the stopgaps in place, or has a written reason and a date
- [ ] You know which images and apps carry their own Ghostscript
- [ ] No gs process owned by a web or print user outside your baseline
- [ ] No shell, download tool or interpreter started under gs or a converter outside your baseline
- [ ] No PostScript, EPS or PDF content behind an image extension in upload folders that you can't explain
- [ ] No new or changed file in a web root, plugin folder or config that you didn't deploy
- [ ] No unexplained outbound connection from a converter or gs process
- [ ] No anonymous print jobs from unknown addresses on shared CUPS queues
- [ ] No unverified checker or proof-of-concept code was run on a production host

**If ANY indicator turns up:** start incident response. One odd file is weak evidence, and a shell started under gs, or an odd file followed by a new file or a new outbound connection, is not. A clean result doesn't clear a host. If an exposed, unpatched host shows any indicator, treat it as compromised until you can show otherwise. Capture state before you restart it (see the advanced forensics section), rebuild the host on a fixed build, and rotate everything it held. Do it in this order: preserve evidence, rebuild, then rotate. New secrets on an unpatched host would go to the same attacker. Rotating signing keys logs users out, so plan for that.

*Sources: the CVE record, the researcher's write-up (third party), The Hacker News (third party), ImageMagick and Pillow source files, CUPS man pages (state on 22 November 2026)*

---

#### DEFENSE-IN-DEPTH FOR DOCUMENT CONVERSION

The fix is Ghostscript 10.08.0, or your distro's fixed package, and a restart of anything that loads it. Artifex gives no workaround. Everything else in this section narrows the exposure or limits the damage, and none of it removes the bug. The table shows what each control covers and what it leaves open.

| Control | What it covers | What it leaves open |
| --- | --- | --- |
| The fixed package, then a restart of anything that loads libgs | The bug, once the package is installed and the process has restarted | Nothing for this CVE |
| ImageMagick delegate line set to none | ImageMagick starting the gs program for EPS, PS, PS2, PS3 and PDF | Apps that call gs directly (CUPS, MediaWiki PdfHandler, Paperless-ngx). Pillow. Drift: a later change to policy.xml. A policy file other than the one you edited |
| ImageMagick coder line for PS, PS2, PS3, EPS, PDF and XPS | ImageMagick reading those formats at all, including builds that use Ghostscript as a library | The same direct callers. Conversions the app needs |
| CUPS queues unshared, remote printing off | Anonymous jobs from untrusted networks | Authenticated users, local users, and any other route to gs on the same host |
| Pillow formats restricted, or no gs on the host | EPS loading through Pillow | Other callers of gs on the same host |
| Locked-down account, container or profile for conversion | What a successful run can do. The Hacker News says an AppArmor profile stopped a compromised interpreter from starting a shell in one test | The bug itself. The researcher says an AppArmor profile blocked the shell in one enforced test on Plesk, and that the live endpoint was not tested |
| WordPress 7.0.4 or 6.9.7, Roundcube 1.6.20 or 1.7.5 | One route each | The Ghostscript bug. These are separate application fixes, not the Ghostscript fix, so updating one does not remove the need for the other |
| -dSAFER | Nothing for this bug | It is the thing being bypassed |

**WAF and scanner coverage on 22 November 2026**

We found no WAF or IPS rule for this bug. Metasploit and Nuclei checks returned no content (COULD NOT VERIFY), and GreyNoise, Tenable, Qualys, Rapid7 and WAF vendor pages returned nothing or could not be read (COULD NOT VERIFY). Don't count on a WAF to block an upload whose content is PostScript behind an image extension, because no source tested one.

| Source | State at the cut-off | What a clean result means |
| --- | --- | --- |
| NVD | Status "Awaiting Analysis". No NVD score of its own, only the VulnCheck score. Published 10 November 2026, last modified 22 November 2026, 05:18 UTC | A tool that waits for NVD analysis may not raise it yet |
| CVE record | Published 9 November 2026 by the VulnCheck CNA, High: CVSS 3.1 7.8 and CVSS 4.0 8.5. Weakness CWE-648. Updated 22 November 2026, 04:06 UTC | A queue that keys on CWE-416 will not match |
| CISA KEV | Not listed (0 matches in a feed of 1790 entries, released 20 November 2026). SSVC of 10 November: Exploitation none, Automatable no, Technical Impact total | A queue that ranks by KEV will not raise it |
| EPSS | 0.00164 (0.16 percent), percentile 0.056, 21 November 2026 | A queue that ranks by EPSS will place it near the bottom. Rank by exposure instead |
| Distro trackers | Debian lists fixed packages. Ubuntu lists "Needs evaluation". SUSE, Amazon Linux and Alpine show open or pending rows. Red Hat has no record | A tracker says a fixed package exists, not that your host runs it |
| Scanner vendors | No finding on Tenable, Qualys or Rapid7 pages (COULD NOT VERIFY) | "Not flagged", not "not exposed" |

*Sources: NVD, the CVE record, CISA KEV feed and SSVC entry, FIRST EPSS data, distro trackers, vendor pages we could read (state on 22 November 2026, 12:30 UTC)*

**The version number trap.** There are three traps here. The first is the distro number. Distro packages keep the old Ghostscript number after a backport, so "gs --version shows 10.05.1" does not mean vulnerable on Debian 13, and a plain "10.08.0" test over-flags a patched distro host. Judge distro packages by the distro advisory. The second is the running process. A host that installed the fixed package and has not restarted a long-running process that loads libgs still runs the old code. The third is a bundled copy: a patched host package says nothing about a copy inside an image or an app. Where we inferred a status, check again when the vendor publishes a notice.

*Sources: Debian security tracker, Ubuntu CVE page, the researcher's write-up (third party), The Hacker News (third party)*

---

**Reducing what reaches Ghostscript**

- Stop untrusted files from reaching a converter you don't need. An app that never needs EPS or PDF to image conversion can turn the converters off.
- Pass untrusted images through a fixed list of accepted formats, and reject the rest before they reach any library (our reading, from the Pillow documentation).
- Check content, not file names. ImageMagick treats files starting "%!" as PostScript and files starting "%PDF-" as PDF, and the extension is only a hint (inferred from the ImageMagick source). Pillow's EPS plugin accepts data starting "%!PS" or the DOS EPS header and ignores the extension (code, from the Pillow source we saved).
- Disable the PDF and PostScript preview providers in Nextcloud if nobody needs them. They are off by default, and an admin has to turn them on (inferred from the default configuration).
- Review MediaWiki wikis that enable PdfHandler and allow uploads, because the extension calls gs for thumbnails (inferred). The researcher reports a reproduction on a wiki set up for anonymous PDF uploads (third party).
- Review Paperless-ngx and similar OCR pipelines: the official image installs the distro ghostscript package (inferred). The researcher says an email attachment through a configured inbox reaches Ghostscript (source-mapped, not executed).
- Apply the Roundcube and WordPress updates, and treat them as separate from the Ghostscript fix.

*Sources: ImageMagick delegate and coder source files, Pillow EPS plugin source, Nextcloud default configuration, MediaWiki PdfHandler configuration, Paperless-ngx Dockerfile and parser, the Roundcube and WordPress advisories, the researcher's write-up (third party)*

**Hardening that limits the damage**

None of this stops the bug. It limits what a successful attempt can do, and it is our advice, not a vendor's. The researcher reports command execution as the account running Ghostscript, so what that account can read, write and reach sets the damage.

- Run conversion as its own unprivileged account, never as root, and never as the account that owns the application code.
- Give that account no shell, no network and no write access outside a scratch directory where the platform allows it.
- Keep web roots and code read-only to the converting account. Let a separate deploy account own the files.
- Restrict outbound traffic from conversion hosts with an allow list at the host firewall, the security group or an egress proxy. It doesn't stop the bug, but it breaks a reverse shell or a tool download after command execution.
- Mount or load only the secrets each service needs, and use short-lived credentials where you can. Rotation after an incident is then a small job.
- Keep print servers and mail servers apart from hosts that hold other secrets.
- In a container, run the process as a non-root user, mount the filesystem read-only where the image allows it, and drop capabilities you don't need. Pin the base image to a version tag, and rebuild on a schedule so that fixed packages reach your images.
- Send logs and process-creation events to a place the host can't change.

*Sources: the researcher's write-up and The Hacker News on containment (third party). The rest is our own advice, not a vendor's.*

**Patch cadence and the quiet window**

This bug gave little notice. The upstream fix is dated 2 September 2026 and Ghostscript 10.08.0 was released on 8 September. The release notes say "This release addresses a number of potential security issues." and name no CVE. The CVE record followed on 9 November and the researcher's write-up on 21 November, about 9 to 11 weeks after the fix. So the news is the disclosure, not a new patch. Jan Schaumann wrote on oss-security (third party opinion): "If GS published a fix on 2026-09-08, then we should assume that this vulnerability was public as of that date."

- Set a written cadence that gets each Ghostscript release, and each distro Ghostscript update, onto every host and image within days, with restarts built in.
- Watch the Ghostscript release notes and your distro's tracker, not only CVE alerts. A release can arrive without a CVE number.
- Keep an emergency path outside the normal window for a bug in a file converter that faces untrusted input.
- Don't mix this bug up with other Ghostscript bugs fixed in 10.08.0. CVE-2026-39919 is a heap-based buffer overflow in the JPEG 2000 output adapter (CVSS 9.8 on v3.1, 9.3 on v4.0, published 15 September 2026). CVE-2026-101258 is a separate -dSAFER bypass rated 7.8, published 6 October 2026. CVE-2026-103226 is a font memory bug. CVE-2026-65640 is the WordPress core fix and CVE-2026-114727 is the Roundcube hardening. Reports on Dropbox and other services are separate Ghostscript bugs, per the researcher and The Hacker News. A host patched for one of them may still lack the fix for this one, so patch to Ghostscript 10.08.0 or later, or to the distro build that carries the fix for this CVE.
- Headlines in a news search on 22 November claim exploitation of other Ghostscript bugs. They are not evidence about this CVE (WEAK, search snippets only).

*Sources: Ghostscript release notes, the CVE record, the oss-security thread (third party opinion), Debian and Ubuntu advisories, the researcher's write-up (third party), The Hacker News (third party) (state on 22 November 2026)*

---

**Monitoring and alerting**

Turn the signals on before you alert on them. A rebuild wipes the host's own logs, so the copy that counts is the one that left the host. Write the queries in your own SIEM's syntax from the patterns in the table. Baseline first: how often your hosts run gs, which accounts run it, and your usual destinations decide the thresholds.

| What to watch | Where it comes from | Alert when |
| --- | --- | --- |
| Build and restart state | The Phase 1 and Verification commands, run on a schedule | A host that takes untrusted files runs a build below the fixed one, or a process still holds the deleted library |
| Policy drift | The policy list, run on a schedule across ImageMagick hosts | The delegate "*" none entry disappears, or a package update replaces policy.xml |
| CUPS sharing | `cupsctl`, run on a schedule | _share_printers or _remote_any turn on again |
| Bundled copies | Image scans for gs and the version inside each image | A new image ships a Ghostscript below the fixed build |
| gs process use | Process-creation events for gs | gs run by a web or print account at a time or from a parent that is not in your baseline |
| Process creation | EDR or audit events for processes started under gs or a converter | A shell, download tool or interpreter that isn't in your baseline |
| Upload folders | A scheduled content-type check on stored uploads | PostScript or PDF content behind an image extension |
| Web roots and config | File integrity monitoring, or a diff against your deployment source | Any change that doesn't come from a deploy |
| Outbound connections | Firewall or flow logs for conversion hosts | A destination the host doesn't normally use |
| Advisories | Vendor pages for Ubuntu, Red Hat, SUSE, Amazon Linux and Alpine, NVD, CISA KEV and EPSS | A status change, a new advisory, or a KEV listing |

---

#### ADVANCED FORENSICS FOR A SUSPECT CONVERSION HOST

A restart destroys the memory of the running processes, and a rebuild wipes the host. We have no source that says what an attempt leaves behind, so volatile state may be the only evidence. On any host that showed one of the signals above, capture first and patch second. Work in order of how fast things disappear: processes and connections first, then memory, then logs, then config and web roots, then the disk.

**Capture volatile state before any restart:**

Bring trusted tools to the host, and send each output to a file on an evidence volume or a remote destination, not to the application disk.

```bash
# run as root. Every process with its parent, owner and start time
ps -eo user,pid,ppid,lstart,args
# The same as a tree, to see what each process started
ps -eo user,pid,ppid,lstart,args --forest
# Listening sockets with their processes
ss -tlnp
# Ghostscript version and package, as the host runs them now
gs --version
dpkg -s ghostscript
rpm -q ghostscript
# Processes that still hold a replaced copy of the Ghostscript library
grep -l 'libgs.*(deleted)' /proc/[0-9]*/maps 2>/dev/null
# CUPS settings and queues as they are now
cupsctl
lpstat -v
# Service log lines kept by the journal
journalctl -u cups --no-pager
```

For established connections, use your EDR or flow logs. Copy the logs, the application and policy config (the ImageMagick policy file, the CUPS config), the upload folders and the web roots to the evidence volume, and hash them as soon as they are there.

If you can, take a memory image as well, with a Linux memory acquisition tool of your choice and its own documentation, or a hypervisor snapshot that includes memory. This document gives no capture commands. A memory image holds every secret the host had, so encrypt it and limit who can read it. Reading one takes specialist tools, so capture it, hash it and hand the analysis to someone who does this for a living. Keep the version output with it.

Then isolate the host: cut its network at the switch, the security group or the hypervisor, and don't shut it down. For a container, don't remove it. Export or snapshot its filesystem with your runtime's tools before you replace it.

**Process hunting for the converting account:**

Run the hunt from the detection section before anything changes the process list. Record each hit in full: the process, its parent and children, its start time, and its sockets from the list you captured.

```bash
# Processes running as web or print users, with their parents
ps -eo user,pid,ppid,lstart,args | grep -E '^(lp|www-data) '
# Ghostscript processes, with their parents and start times
ps -eo user,pid,ppid,lstart,args | grep -E '(^| )gs( |$)'
# run as root. One process in detail: owner, parent and state
cat /proc/<pid>/status
```

A shell, a download tool or an unknown binary under gs, owned by the converting account and not in your baseline, is an incident. If its start time lines up with an upload, an inbound mail or a print job, that is the sequence to chase. A clean result doesn't clear the host: the command lists live processes only, and anything that has already exited leaves nothing.

**Why a command-execution compromise means rebuilding the host:**

Once an attacker has run commands as the converting account, everything that account can write may have changed: upload folders, caches, temp directories, plugin and web folders, and any file the application writes. The process list, the file listing and the logs come from a system the attacker has touched, so a scan that finds nothing proves nothing. A fixed build stops new attempts and removes nothing that is already installed. This is our reasoning, not a vendor statement, and it is standard practice after a command-execution compromise. We have no source that says this bug gives an attacker more than the rights of the account running Ghostscript. Where that account is root, or where conversion shares an account with the application, treat the whole host as compromised.

If a host shows a shell, a new file or an unexplained outbound connection, or you can't rule one out, rebuild it:

- Preserve first: process and socket state, logs, memory if you can, and a disk image or snapshot.
- Rebuild from a known-good image that carries a fixed build, not from a copy of the old system disk.
- Restore content and data only after you have checked them. Don't restore web roots, plugin folders, scripts, cron entries, unit files or configuration from the old host without reading them.
- Rotate everything the account could read or reach (see What the converting account could read under the detection section). Rotate after the rebuild, not before: new secrets on an unpatched host would go to the same attacker. Rotating signing keys logs users out, so plan for that.
- Treat every container that ran from a compromised image or on a compromised host as exposed, with the secrets mounted into it.
- Check the neighbours: every host that the machine could reach with the credentials it held.

Patching in place is acceptable for a host with no indicator and no link to an attempt.

**Evidence handling:**

- Record who collected what, when, from which host, and with which tool and version. Record the host's clock offset from UTC, and keep every timestamp in UTC.
- Hash each item with SHA-256 right after you collect it, write the hashes to a separate file, and keep a read-only copy off the host.
- Work on copies. Keep the originals untouched.
- Encrypt memory images, logs and exports, at rest and in transit, and limit who can read them.
- Log every command you run on the suspect host, and note whether it only read or changed something.
- If you expect legal action or an insurance claim, image the disk (a volume snapshot on a cloud host) before you rebuild.

**Building the timeline:**

Put every source on a single UTC timeline and mark each entry: exposure (an exposed build was running), attempt (a suspect upload, mail or print job), or possible success (a process, a file or a connection that isn't in your baseline).

| Source | What it gives you |
| --- | --- |
| Package and restart history | When each host last ran an exposed build, and when it installed and restarted into the fix |
| Upload and mail records | Who sent a file with PostScript or PDF content behind an image extension, and when |
| CUPS logs | Jobs from unexpected addresses, and the time of each |
| Process start times | The `lstart` column for every hit in the process hunt |
| File times | Creation and change times of files in upload folders, web roots and config |
| Firewall, flow and proxy logs | Outbound connections, and what the proxy saw of the client |
| Platform logs | Cloud audit logs and instance events, and for containers the orchestrator events |
| Credential use | Where the secrets from the host were used afterwards, and from which addresses |

No published attack pattern exists for this CVE, so we can't tell you which sequence to look for. The sequence to chase is a suspect upload, mail or print job followed by a process, a file or a connection that isn't in your baseline.

**The window to review:**

No attacks are reported at the cut-off. The Hacker News said on 22 November that "there have been no reports of it being used in attacks" (third party, not CISA or Artifex). CISA's SSVC entry of 10 November says Exploitation none, and the CVE is not in KEV. A public proof of concept is partial: the researcher's write-up shows a memory-write step and, by its own words, does not run a shell command or touch host files. No full command-execution chain is published. The researcher says one large production service mitigated its affected path on 10 November, and says it reached Ghostscript through a signed-out request (researcher-stated, unconfirmed by that service). Nobody was reported compromised.

| Window | Starts | Use it when |
| --- | --- | --- |
| Minimum (our reading) | 2 September 2026 | Always. It is the date of the upstream fix commit, the earliest date anyone could have worked from the public change. The exact time the commit became public was not verified |
| Wider (our reading) | 12 August 2026 | WordPress hosts. It is the date WordPress released 7.0.4 with its own fix (researcher and The Hacker News). It is a margin. No source says anyone attacked then |
| Maximum (our reading) | As far back as your logs go | Internet-facing hosts that take anonymous input and hold sensitive data. No start version is given anywhere, so the first vulnerable release COULD NOT VERIFY |

Don't start later than 2 September. The release (8 September), the researcher's public teaser (25 September), the CVE record (9 November) and the write-up (21 November) all came after the fix was already public. The oss-security announcement was posted on 21 November, and the reply the CVE record links is archived under 22 November. The window ends when each host runs a fixed build and its processes have restarted, not on the day you installed the package.

*Sources: Ghostscript fix commit and release notes, the CVE record, CISA SSVC entry and KEV feed, The Hacker News (third party), the researcher's write-up (third party), oss-security (third party), the WordPress advisory and release (state on 22 November 2026, 12:30 UTC)*

**Public repositories named after the CVE:** GitHub search at the cut-off returned 3 repositories for each query, the CVE ID and Upload2Shell, all created on 22 November 2026 (06:16, 08:27 and 11:21 UTC). We did not open them, so what they contain is unknown. The search can undercount, and we name none. Running unknown proof-of-concept code is a common way to get compromised, so don't test your hosts with it. If anyone on your team ran one against a real host or a laptop, treat that machine as suspect. We have no hashes, addresses or request signatures for this CVE, so there is nothing to put on a blocklist.

**When to bring in outside help:**

- A shell, download tool or interpreter started under gs or a converter, and you can't explain it from your baseline
- A suspect upload, mail or print job followed by a new file or an outbound connection, on a host that wasn't patched at the time
- Secrets from a suspect host were used from addresses you don't recognise
- You hold a memory image and nobody on the team can read it
- The conversion account on a suspect host was root, or shared with the application
- A host was already restarted or rebuilt and its logs rotated, and it handled customer or regulated data. The question then changes from "was it hit" to "what could the converting account read", and the notification duties in the compliance section apply

Do not wipe or rebuild a suspect host before you have preserved it.

---

## BUSINESS IMPACT ANALYSIS

### Financial impact scenarios for the Ghostscript chain

The scenarios stay qualitative. No source for this bug gives cost figures, so none are given here. Labels follow the rest of this analysis: the CVE record rates the bug High (CVSS 3.1 7.8, CVSS 4.0 8.5). The CRITICAL tier used below is our reading, not the CVE's rating. No attacks reported at the cut-off.

#### Scenario 1: Prevention (patch this week)

**Costs:**

- Staff time: finding every place Ghostscript runs (host packages, container images, application bundles, print servers, mail and wiki hosts), then an upgrade for each
- Version traps: distro builds keep old version numbers after a backport, so "gs --version shows 10.05.1" does not mean vulnerable on Debian. Each platform needs its own check against its own advisory
- Restarts: a long-running process that loads the Ghostscript library keeps the old copy in memory until it restarts, so PHP-FPM and similar services need a restart after the upgrade (inferred, our reading)
- Separate copies: per the researcher and The Hacker News, updating the host package does not update a copy bundled in a container image or an application
- Platforms with no confirmed fix: Ubuntu, Red Hat, SUSE Linux Enterprise and Amazon Linux had no confirmed fixed package for this CVE at the cut-off, so those hosts need stopgaps and a daily look at the vendor page
- Downtime: usually none for a package upgrade on a conversion host, a short window for a print server

**Benefits:**

- No breach costs, no notifications, no letters from regulators
- An accurate list of where Ghostscript runs and which application feeds it files. You will want it for the next advisory: Ghostscript 10.08.0 also fixes other CVEs, and those are separate bugs
- One fix covers the whole class of callers on that host (ImageMagick, Pillow, CUPS filters, document previews), because they all end at the same interpreter

*Sources: Artifex Ghostscript release notes, CVE record, Debian, Ubuntu, Red Hat, SUSE and Amazon Linux pages, the researcher's write-up, The Hacker News*

---

#### Scenario 2: Compromise of a shared print queue or a public upload form

An untrusted file reaches an affected Ghostscript with no login. The researcher reports command execution as the account running Ghostscript (lp for CUPS, www-data for web and mail) in the setups the researcher tested. We treat that as a claim, and nobody has confirmed it outside the write-up.

**Immediate impact:**

- An attacker with command execution as the print or web account can read what that account can read: spool files, uploaded documents, application configuration and database passwords stored where the web account can open them
- Print servers and upload hosts are often trusted by other systems, so the account becomes a step toward them
- Incident response, forensics and a pause on the affected feature while you work out what was reached

**Business consequences (qualitative):**

- Customer and staff documents that passed through the queue or the upload form may have been read
- Regulators may need to be told if personal data was reached (see the compliance section)
- Secrets that the account could read must be treated as exposed and rotated

*Sources: the researcher's write-up (researcher claim, attributed), The Hacker News, CVE record, CISA ADP entry in the CVE record*

---

#### Scenario 3: Quiet compromise with no crash and no log entry you recognise

We found no public indicators of compromise for this bug. Artifex, the CVE record and the researcher publish no exploit signature. A converter that runs a command as its own account may leave little beyond a short-lived child process.

**What this means for the business:**

- "We found nothing" is weak evidence here. It is weaker than it would be for a bug with a known fingerprint
- A mail host that thumbnails attachments on view, or a site that converts uploads in the background, can run the attacker's file with nobody at the keyboard (researcher-reported for Roundcube, 5 of 5 trials in the researcher's setup)
- The cost shows up later: a credential used from a strange place, a changed file, a customer complaint

**What reduces the risk:**

- Patching removes the cause. Hunting only finds symptoms
- Containment (a locked-down account, no shell, no network for the converter) limits the damage even if the interpreter is compromised. The researcher says an AppArmor profile blocked the shell in one test, and The Hacker News repeats it (third party)

*Sources: CVE record, the researcher's write-up, The Hacker News, our reading*

---

#### Scenario 4: Internal document pipeline behind a login

MediaWiki with PdfHandler, Paperless-ngx (inferred) and Nextcloud with the optional PDF or PostScript preview providers turned on all call Ghostscript on files that staff or customers upload. WordPress core is in the same group: its fix, CVE-2026-65640, needs an Author or higher account.

**Business consequences (qualitative):**

- The attacker needs an account first, or a way to get a file in through a mailbox or an upload share. That lowers the chance, not the damage
- A contributor account, a compromised staff login or a shared upload link is enough to turn a document feature into command execution as the web account
- These pipelines often hold the most sensitive files you have: contracts, invoices, scans

*Sources: WordPress advisory and CVE-2026-65640 record, MediaWiki PdfHandler and Nextcloud and Paperless-ngx project files (inferred), the researcher's write-up*

---

#### Scenario 5: Hosts with no confirmed fix and bundled copies you cannot patch

Debian 13 and Debian 12 (with the security repository) have fixed packages. Ubuntu is not confirmed. Red Hat has no record for this CVE. SUSE has mostly open rows, with a released fix only for openSUSE Tumbleweed. Amazon Linux shows ghostscript on AL2, AL2023 and AL2027 Preview as "Pending Fix". Alpine stable branches had no fixed build at the cut-off.

**What this means for the business:**

- You are waiting on vendors while the disclosure is public. The fix has been in the upstream project for 11 weeks
- Appliances and images that bundle their own Ghostscript depend on their suppliers
- You need written answers from suppliers, stopgaps in the meantime and a named person who patches the day a fixed build appears

*Sources: Debian, Ubuntu, Red Hat, SUSE, Amazon Linux and Alpine pages, Artifex Ghostscript release notes*

---

### Operational impact timeline for the Ghostscript response

**Hour 0-24: Inventory and patching**

- Platform and ops teams pulled off roadmap work
- A list of every host, container image and appliance that has Ghostscript: version or distro build, and which application feeds it files (ImageMagick, Pillow, CUPS filters, document previews, mail or wiki thumbnails)
- Which of those take files from people you do not control: shared print queues, public upload forms, inbound mail, anonymous wiki uploads
- Fixed builds installed on Debian 13, Debian 12 (security repository) and anywhere a fixed package exists, with Ghostscript 10.08.0 where you build it yourself
- Stopgaps on hosts with no fix: delegates blocked in the ImageMagick policy, print queues no longer shared with untrusted networks
- Long-running services that load the Ghostscript library restarted after the upgrade

**Day 2-7: Verification**

- Confirm the version or distro build on every host and inside every container image, because each image carries its own copy
- Log review for unexpected shells under Ghostscript or converter processes, and for PostScript or PDF files stored under image names
- Chasing suppliers and distros for written answers: Ubuntu (not confirmed), Red Hat (no record), SUSE, Amazon Linux, Alpine stable
- Application updates applied where relevant: WordPress 7.0.4 or 6.9.7, Roundcube 1.6.20 or 1.7.5. These are separate application fixes and do not replace the Ghostscript update

**Week 2-4: Hardening**

- Run document conversion under a locked-down account, container or profile with no network and no shell (our reading)
- Pillow code paths that open untrusted images pass only the formats they need
- ImageMagick policy kept in version control, and checked after package updates
- Detection rules for shells started under converters, and longer log retention

**Month 2-6: Only if you found a compromise**

- Regulator questions, customer communications, possible claims
- Audit follow-ups and insurer reviews

*Sources: Artifex Ghostscript release notes, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux and Alpine pages, WordPress and Roundcube advisories, ImageMagick, CUPS and Pillow documentation, our reading*

---

### Cost-benefit analysis of Ghostscript response options

| Option | Effort | What's left exposed | Verdict |
| --- | --- | --- | --- |
| Upgrade Ghostscript (10.08.0 or the distro build with the fix) and restart services that load the library | A package upgrade per host, a rebuild per container image, a restart for library-loading services | Nothing known for this CVE once the running copy is the fixed one. Separate copies bundled in other images stay open until rebuilt | Do this |
| Block ImageMagick delegates and the PostScript and PDF coders in the policy file | Edit the policy.xml that ImageMagick actually loads, then confirm with the policy listing | Apps that call Ghostscript directly (CUPS, MediaWiki, Paperless-ngx) are not covered. PDF and PostScript conversion that the app needs stops working | A stopgap for days, not a fix |
| Stop sharing print queues with untrusted networks | Three CUPS commands, then a check that nobody outside can submit jobs | Everything not routed through CUPS. Computers that print through the server stop working until let back in a narrower way | A stopgap where CUPS faces an untrusted network |
| Restrict Pillow to the formats the app needs | A code change in each app that opens untrusted images | Callers outside Pillow | A layer, not a fix |
| Run conversion in a locked-down account, container or profile | An architecture change per pipeline | The interpreter is still compromised, but with less reach | Containment, not a substitute for updating |
| Update only WordPress or only Roundcube | An application update | The Ghostscript bug. Those fixes close one route each | Do it, and patch Ghostscript too |
| Wait | None today | Everything, on any host where untrusted files reach an affected Ghostscript | Not acceptable where files from outsiders reach Ghostscript. The fix has been public since 8 September 2026, the CVE record since 9 November, and no attacks were reported at the cut-off, which can change quickly |

*Sources: Artifex Ghostscript release notes, CVE record, ImageMagick security policy and upstream policy files, CUPS man pages, Pillow documentation, the researcher's write-up, The Hacker News*

---

## COMPLIANCE & LEGAL REQUIREMENTS

### Regulatory notification obligations if a Ghostscript host is compromised

If you find signs of compromise, these timelines may start running. A clean upgrade triggers none of them. Whether personal data was reached is a legal judgment that depends on what the account running Ghostscript could read, and an attacker who runs commands as that account can read what the application can read. This is a summary, not legal advice.

#### GDPR (EU) and UK GDPR

- **Timeline:** 72 hours to notify the supervisory authority after becoming aware of a personal data breach, unless it's unlikely to put people at risk
- **Individuals:** without undue delay if the risk to them is high
- **Fines:** up to EUR 20 million or 4% of worldwide annual turnover (UK: GBP 17.5 million or 4%)
- *Source: GDPR Articles 33, 34 and 83*

#### NIS2 (EU essential and important entities)

- **Early warning:** within 24 hours of becoming aware of a significant incident
- **Incident notification:** within 72 hours
- **Final report:** within one month
- *Source: Directive (EU) 2022/2555, Article 23*

#### India: CERT-In and DPDP

- **CERT-In:** report covered cyber incidents, including unauthorised access and compromise of systems, within 6 hours of noticing them
- **DPDP Act 2023:** breach-reporting duties phase in under the DPDP Rules 2025, so check whether they apply to you yet
- *Source: CERT-In Directions under Section 70B(6) of the IT Act, 28 April 2022*

#### SEC (US-listed companies)

- **Timeline:** Form 8-K Item 1.05 within four business days of determining that a cybersecurity incident is material
- *Source: SEC cybersecurity disclosure rules (2023)*

#### HIPAA (US healthcare data)

- **Timeline:** notify affected individuals without unreasonable delay, and no later than 60 days after discovery. HHS too, and the media if more than 500 residents of a state or jurisdiction are affected
- *Source: 45 CFR 164.400-414*

#### US state breach laws

- All 50 states have breach notification laws. Timelines and triggers vary by state

---

### Documentation checklist for the Ghostscript response

**Create and maintain:**

- [ ] **Incident timeline** with precise timestamps
    - When the issue became public (fix commit 2 September 2026, Ghostscript 10.08.0 released 8 September 2026, CVE record published 9 November 2026, the researcher's write-up dated 21 November 2026)
    - When your organization learned about it
    - When inventory, patching, restarts and verification finished
- [ ] **Technical details:**
    - Inventory of hosts, images and appliances with Ghostscript: version or distro build, which application feeds it files, and whether untrusted files can reach it
    - Versions before and after patching, with restart times for library-loading services
    - ImageMagick policy state before and after, and the CUPS sharing settings
    - Any evidence of compromise
    - Stopgaps applied and removed
- [ ] **Business impact assessment:**
    - Systems and data at risk
    - Customer impact
- [ ] **Decision log:**
    - Who authorized what, and why
    - Risk decisions on hosts that waited for a distro or vendor fix, and on bundled copies
    - The reasoning behind any "no compromise" conclusion. We found no published indicators of compromise, so "we found nothing" is weak evidence
- [ ] **Communications log:**
    - Who was told what, and when

**Retention:** follow your industry's record-keeping rules. Seven years is a common default.

---

### Insurance considerations for a Ghostscript incident

- [ ] Check that your cyber policy is active and what it covers (investigation, business interruption, liability, notification costs)
- [ ] Check the notification deadline in the policy. Many require notice within 24 to 72 hours of a suspected incident
- [ ] Check whether you must use the insurer's panel of response firms
- [ ] Keep evidence of your patching speed: dates, versions and restart times. Insurers look hard at known, unpatched vulnerabilities

**Call your broker straight away if:**

- You find indicators of compromise
- You're running on stopgaps for more than a few days on a host that takes files from outsiders
- You're unsure what your policy covers

---

## DECISION MATRIX

### What should we do right now about Ghostscript?

The tiers below are our reading. The CVE record rates the bug High (7.8 and 8.5), never Critical. CRITICAL here means an affected Ghostscript that untrusted people can reach with no login.

| Your situation | Immediate action | Priority | Timeline |
| --- | --- | --- | --- |
| Ghostscript 10.08.0 or a distro build with the fix (checked against its advisory), and library-loading services restarted | Document it, keep monitoring | LOW | This week |
| Fixed package installed, but a long-running service that loads the library has not restarted | Restart it | HIGH | Today |
| CUPS server with a shared queue that accepts unauthenticated jobs from an untrusted network, Ghostscript before 10.08.0 or without the distro fix | Patch where a fix exists. Stop sharing the queue with untrusted networks or require authentication meanwhile | CRITICAL (our reading) | Today |
| Roundcube before 1.6.20 or 1.7.5 with ImageMagick and Ghostscript present | Update Roundcube and patch Ghostscript. Block ImageMagick delegates until Ghostscript is fixed | CRITICAL (our reading) | Today |
| WordPress with public-upload plugins the researcher names (Forminator, Essential Addons for Elementor) on a host with Imagick and Ghostscript | Patch Ghostscript, update WordPress (7.0.4 or 6.9.7), and block ImageMagick delegates until then. No fixed plugin version is stated by any source we saw | CRITICAL (our reading) | Today |
| Any app that passes anonymous uploads or email attachments to ImageMagick, GraphicsMagick, Pillow EPS loading or Ghostscript | Patch Ghostscript, restrict formats, block delegates meanwhile | CRITICAL (our reading) | Today |
| The same paths behind a login (WordPress core needs Author or higher) | Patch Ghostscript and the application | HIGH | 48 hours |
| MediaWiki with PdfHandler, Nextcloud with PDF or PostScript preview providers enabled, Paperless-ngx (inferred) | Patch Ghostscript. Turn off the optional preview provider if you do not need it | HIGH | 48 hours |
| Debian 13 or Debian 12 with the security repository | Install the fixed package (deb13u2 or later, deb12u9 or later), restart library-loading services | HIGH until installed | Today |
| Ubuntu | Ubuntu has not confirmed a fix for this CVE. Apply the stopgaps, install the USN-8949-1 packages (our reading, not confirmed for this bug) and watch the Ubuntu CVE page | HIGH | 48 hours |
| Red Hat family, SUSE Linux Enterprise, Amazon Linux, Alpine stable | No fixed package at the cut-off. Stopgaps now, upgrade the day a fix ships | HIGH, CRITICAL (our reading) if untrusted files reach it | Today or 48 hours |
| Container image or appliance that bundles its own Ghostscript | Rebuild or ask the supplier in writing. Updating the host does not touch it | HIGH | 48 hours |
| Host with no Ghostscript, or nothing untrusted reaches it | Document it. Take the update in the normal window | LOW | Normal window |
| Don't know where Ghostscript runs | Run the version checks in this document | CRITICAL (our reading) | 2 hours |
| On an exposed host: a shell started under Ghostscript or a converter, PostScript or PDF files stored under image names | Start incident response. Capture the process list, network connections and logs before any restart | EMERGENCY | Immediately |

*Sources: CVE record, Artifex Ghostscript release notes, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux and Alpine pages, WordPress and Roundcube advisories, the researcher's write-up, our reading*

---

### Risk decision framework for Ghostscript hosts

**For each host, container image and application that can call Ghostscript:**

```
Step 1: Who can hand it a file (take the first line that matches)
- Anyone with no login (shared print queue, public upload form,
  inbound mail, anonymous wiki upload)                       HIGH
- Logged-in users only (WordPress Author or higher, wiki
  accounts, document uploads by staff)                       MEDIUM
- Only trusted staff, through a reviewed process             LOWER
- Nothing untrusted reaches Ghostscript, or no Ghostscript   LOWER

Step 2: Version and build
- Upstream Ghostscript before 10.08.0                        HIGH, patch today
- Distro build: judge by the distro advisory, not by
  the version number                                         HIGH until its fix runs
- Ubuntu, Red Hat, SUSE Linux Enterprise, Amazon Linux, Alpine stable:
  no confirmed fix at the cut-off                            HIGH, use stopgaps
- Fixed build, library-loading services restarted            LOWER
- Bundled copy inside an image or application                HIGH until rebuilt

Step 3: Data and blast radius
- Personal, payment or health data, or secrets for other
  systems that the account running Ghostscript can read      HIGH
- Public content only, no secrets, restricted network paths  LOWER

Step 4: Action
Anonymous reach + any other HIGH       Patch today, stopgaps until then
Login required + any other HIGH        Patch within 48 hours
Everything else                        Patch in the normal window
```

Two situations are easy to miss. A converter built with the Ghostscript library inside a long-running process keeps the old copy in memory until that process restarts (inferred, our reading). And -dSAFER, which every ImageMagick delegate line that starts Ghostscript and the Pillow EPS plugin already pass, is the protection this bug gets around, so those setups are in scope.

*Sources: CVE record, Artifex Ghostscript documentation, ImageMagick delegate list and Pillow source (inferred), the researcher's write-up, our reading*

---

### Go/no-go checklist before emergency Ghostscript patching

**Before you approve emergency patching:**

- [ ] Backup or snapshot taken (for cloud hosts an image of the current state, with the previous package version still available so you can go back)
- [ ] Rollback plan written down. A rollback puts the vulnerable version back, so give it a time limit and keep the stopgaps on while it lasts
- [ ] Stakeholders told about the change and any service restart
- [ ] Short test plan agreed (uploads still convert, thumbnails still render, print jobs still run, previews still load)
- [ ] Someone on call during and after the change
- [ ] Restart method confirmed (services that load the library, a rebuilt image for containers)
- [ ] Right fix confirmed for each platform: the package that your distro's advisory names, not an upstream number
- [ ] Hosts you suspect: process list, network connections and logs captured before the restart

**If you can't tick every box:**

- Apply the stopgaps on the exposed hosts (see the QUICK REFERENCE CARD)
- Restrict access to trusted networks where you can
- Take the exposed feature offline for now if neither of those is possible

---

## FREQUENTLY ASKED QUESTIONS

### Executive questions about Upload2Shell

**Q: How do we know if we're affected?**

**A:** Ask IT three questions. Where does Ghostscript run on our servers and in our container images, and which version or distro build is each one? Which applications hand it files: print queues, upload forms, mail, wiki or document previews? Can an outsider get a file to those applications without a login? Ghostscript before 10.08.0 is affected per the CVE record. No start version is given anywhere, so we say "before 10.08.0" and no more. Distro builds keep old numbers after a backport, so IT has to check them against the distro advisory. Hosts without Ghostscript have no path. If a hosting company or platform runs your servers, ask in writing. The version commands are in the QUICK REFERENCE CARD.

*Sources: CVE record, Artifex Ghostscript release notes, Debian and Ubuntu pages, The Hacker News*

---

**Q: What's the worst that could happen?**

**A:** An outsider sends a crafted PostScript or PDF file, possibly behind an image name, to an application that passes it to Ghostscript, and gets commands run as the account that runs Ghostscript. That is the impact in the CVE text, and the CISA ADP entry rates Technical Impact "total". From there they can read what the application can read, such as database passwords and customer files. The researcher reports this in the setups the researcher tested (a print queue, a mail client, upload forms), and those results are not independently confirmed. It does not give root unless Ghostscript runs as root (inferred).

*Sources: CVE record, CISA ADP entry in the CVE record, the researcher's write-up (researcher claim, attributed)*

---

**Q: Is anyone exploiting this?**

**A:** No attacks reported at the cut-off. The Hacker News said on 22 November that "The flaw, tracked as CVE-2026-125396, was fixed on September 8, and there have been no reports of it being used in attacks." That is a third party, not CISA or Artifex. CISA's ADP entry shows SSVC Exploitation "none" as of 10 November, the CVE is not in the CISA exploited list (0 matches in a feed of 1790 entries, released 20 November 2026), and the EPSS score is 0.00164 (0.16 percent, percentile 0.056, 21 November). EPSS is a one-day-old model score, not evidence of safety. A public proof of concept exists in part: the researcher's write-up shows a memory-write step, not a full command-execution chain, and the researcher marks each per-application exploit "Not published". Three GitHub repositories came back for each of two searches, all created on 22 November. We did not open them and we name none of them. Some news results in a search mention exploitation of other Ghostscript bugs, which is not evidence about this CVE. This can change quickly, so check again before you rely on it.

*Sources: The Hacker News, CISA ADP entry and CISA KEV feed, FIRST EPSS API, the researcher's write-up, GitHub repository search (count only)*

---

**Q: Is this the same as CVE-2026-39919 or CVE-2026-101258?**

**A:** No. They are separate Ghostscript bugs with their own records, and coverage mixes them up.

- CVE-2026-39919: a heap-based buffer overflow in the JPEG 2000 output adapter, fixed in 10.08.0, published 15 September 2026, CVSS 9.8 (3.1) and 9.3 (4.0). It is the WordPress PDF upload bug that BleepingComputer covered in October (WEAK, search snippet)
- CVE-2026-101258: a separate -dSAFER bypass from Red Hat's CNA, published 6 October 2026, rated 7.8. Ubuntu lists it in USN-8949-1 and Debian lists it in DLA-4914-1. The credits differ
- Also separate: CVE-2026-65640 (WordPress core fix), CVE-2026-114727 (Roundcube hardening) and CVE-2026-103226 (a font memory bug listed in the same Ubuntu and Debian notices)

This analysis covers CVE-2026-125396 only. Debian's DSA-6516-1 and DLA-4914-1 list several of these CVEs together, so one update can fix more than one of them. Do not merge their facts.

*Sources: CVE records for CVE-2026-39919 and CVE-2026-101258, Debian DSA-6516-1 and DLA-4914-1, Ubuntu USN-8949-1*

---

**Q: Does -dSAFER protect me?**

**A:** No. This bug gets around -dSAFER, so it is not a mitigation. Ghostscript has had SAFER on by default since 9.50, which means default setups are the attacked setup. Every ImageMagick delegate line and the Pillow EPS plugin already pass -dSAFER and are still in scope. Do not reach for -dNOSAFER or -dDELAYSAFER either. Artifex says that with those, "PostScript programs are allowed to read, write, rename or delete any files in the system that are not protected by operating system permissions." Update Ghostscript instead.

*Sources: Artifex Ghostscript usage documentation, CVE record, ImageMagick delegate list and Pillow source (inferred)*

---

**Q: Was Google affected?**

**A:** The researcher says so, and we cannot confirm it. The researcher's write-up says a signed-out request for an attacker-hosted file reached Ghostscript 10.05.0 in the image and document processing of a Google production service, with a bounded file read as proof, and that the service mitigated the affected path on 10 November 2026. The Hacker News (third party) reports that the research reached production services including Google, which fixed the affected path. We found no Google statement. We do not name the product, and nothing here says Google was breached or compromised. The researcher's earlier teaser (25 September 2026) named many companies it said it had run code on without a login. The researcher and The Hacker News say reports for Dropbox and other unnamed services are separate Ghostscript bugs, not this CVE, and that WordPress core needs a login. Treat the teaser as a claim.

*Sources: the researcher's write-up (researcher claim, attributed), The Hacker News (third party)*

---

**Q: If we updated WordPress or Roundcube, are we safe?**

**A:** No. Those are separate application fixes, not the Ghostscript fix. WordPress 7.0.4 (and 6.9.7) fixed CVE-2026-65640, a remote code execution route through a malicious PostScript upload by an Author level user or higher with Imagick and Ghostscript in use. Roundcube 1.6.20 and 1.7.5 fixed unsafe image handling under CVE-2026-114727, and that advisory does not name Ghostscript or CVE-2026-125396. It is app-level hardening that the researcher links to this chain, so we do not say Roundcube "fixed Upload2Shell". The Hacker News says the WordPress fix and the Ghostscript fix "cover different points in the same chain, so updating one does not remove the need for the other." Patch Ghostscript too. The public-upload plugins the researcher names (Forminator, Essential Addons for Elementor) have no fixed version stated in any source we saw.

*Sources: WordPress advisory and CVE-2026-65640 record, Roundcube advisory and news post, The Hacker News, the researcher's write-up*

---

**Q: Why is our tier higher than the CVSS score?**

**A:** Our reading. The CVE record rates the bug High: CVSS 3.1 7.8 and CVSS 4.0 8.5, both from the CNA (VulnCheck), never Critical. Both vectors use attack vector Local, which scores Ghostscript as a local file processor. The remote path comes from the application in front of it, so a scorer who looks only at Ghostscript sees a local bug. The researcher reports command execution in the setups the researcher tested, reached over the network through print jobs, email and web uploads, and The Hacker News repeats that (third party). Where an affected Ghostscript is reachable with no login, we rate it CRITICAL. That tier is our judgment. SUSE says "important", Amazon Linux says Important (CVSS 7.8), and Ubuntu says priority Medium with a CVSS 3 score of 7.8 High. NVD shows "Awaiting Analysis" and no score of its own.

*Sources: CVE record, NVD, SUSE, Amazon Linux and Ubuntu pages, the researcher's write-up, The Hacker News, our reading*

---

**Q: Is Ubuntu fixed?**

**A:** Not confirmed. Ubuntu's CVE page shows priority Medium and status "Needs evaluation" on all seven releases (26.10, 26.04 LTS, 24.04 LTS, 22.04 LTS, 20.04 LTS, 18.04 LTS and 16.04 LTS), last updated 18 November 2026. Ubuntu shipped a Ghostscript notice, USN-8949-1, on 21 October that the researcher says covers this bug. Ubuntu's own CVE page does not yet say so. The saved notice page shows only two CVE numbers, and a third entry that reads "Paulos Yibelo discovered that Ghostscript did not properly validate certain operands when loading fonts." Its CVE number is not visible, and it is likely this CVE (inferred). So installing the USN-8949-1 package is sensible, but we cannot tell you it fixes this bug. Watch the Ubuntu CVE page and apply the stopgaps meanwhile.

*Sources: Ubuntu CVE page and USN-8949-1, the researcher's write-up (researcher-stated), our reading*

---

**Q: Why did we hear about this so late?**

**A:** The fix was upstream first. The fix commit is dated 2 September 2026, and Ghostscript 10.08.0 shipped on 8 September. The release notes say "This release addresses a number of potential security issues." and name no CVE. The CVE record was published on 9 November, NVD followed on 10 November, and the researcher's write-up is dated 21 November. So the news is the disclosure, not a new patch. Jan Schaumann wrote on oss-security (third party opinion): "If GS published a fix on 2026-09-08, then we should assume that this vulnerability was public as of that date." A tool that waits for a CVE record had nothing until 9 November. The fix is 11 weeks old.

*Sources: Artifex Ghostscript release notes, fix commit, CVE record, NVD, oss-security (reply by a third party), the researcher's write-up*

---

**Q: We use a hosting panel, a managed host or an appliance. Do we need to do anything?**

**A:** Get a written answer from the provider: is the product affected, which Ghostscript is inside it, and when will the fix ship? Panels and appliances often bundle their own copy, and updating the host does not update it. We found no supplier statements on this bug in our sources, so ask. Until a supplier answers, keep untrusted files away from conversion features where you can, and keep admin interfaces off untrusted networks. One data point from the researcher: on Plesk with Roundcube 1.6.17 an AppArmor profile blocked the shell in an enforced test, and the live endpoint was not tested.

*Sources: the researcher's write-up (researcher claim), vendor pages (no statement found)*

---

**Q: How long does patching take, and will it break things?**

**A:** For most hosts it is a package upgrade plus a restart of anything that loads the Ghostscript library. A Ghostscript started fresh for each job picks up the new package on the next job (inferred, our reading). Containers need a rebuilt image and a redeploy. Blocking ImageMagick delegates is faster but breaks PDF and PostScript conversion that an app may need, and it does not help apps that call Ghostscript directly. Test that uploads convert, thumbnails render, print jobs run and previews load.

*Sources: Artifex Ghostscript release notes, ImageMagick documentation, our reading*

---

**Q: Should we tell our customers?**

**A:**

- If you patch and find no sign of compromise, this is routine maintenance, and usually no notification is needed.
- If you find indicators of compromise, talk to legal straight away. GDPR, NIS2, CERT-In, HIPAA, SEC and US state laws may all apply, some with deadlines measured in hours.

---

**Q: Should we pay for outside help?**

**A:** Yes if you see any sign of compromise, run print servers or public upload features on affected Ghostscript, work in a regulated industry, or depend on appliances and images you cannot patch. Probably not if you have a handful of hosts on Debian with the fix and a team that can patch and restart today.

---

### Technical questions about Upload2Shell

**Q: How do we check the Ghostscript version, and is the build fixed?**

**A:** `gs --version` prints the version. A host is vulnerable if it is below 10.08.0 and is not a distro-patched build. Distro builds keep the old number: Debian 13 needs 10.05.1~dfsg-1+deb13u2 or later, and Debian 12 needs 10.0.0~dfsg-11+deb12u9 or later from the security repository (the release pocket deb12u8 is still marked vulnerable). Ubuntu: nothing is confirmed. None of these commands was run by us, and gs, magick and convert are not installed on the research machine. The syntax is checked against saved documentation where noted.

```bash
# Ghostscript version
gs --version
# Debian and Ubuntu: installed package and version (compare with the Debian and Ubuntu lines above)
dpkg -s ghostscript
dpkg -l 'libgs*'
# RPM distros: installed package
rpm -q ghostscript
# Alpine: installed package with its version
apk info -v | grep ghostscript
# Homebrew: installed version
brew list --versions ghostscript
```

*Sources: Artifex Ghostscript release notes, Debian tracker, dpkg, rpm and apk documentation (our reading for apk and brew)*

---

**Q: How do we check what ImageMagick will hand to Ghostscript?**

**A:** Look at the formats, the policy and the delegates. Expect the delegate "*" with rights none if the stopgap is in place. ImageMagick 6 uses identify for the policy listing (our reading, not in the ImageMagick documentation we checked).

```bash
# ImageMagick 7: which formats are enabled (look at EPS, PS, PS2, PS3, PDF and XPS)
magick -list format
# ImageMagick 6: the same listing
convert -list format
# ImageMagick 7: the active security policy
magick identify -list policy
# ImageMagick 6: the active security policy
identify -list policy
# ImageMagick 7: the delegate command lines (what it prints is inferred)
magick -list delegate
```

ImageMagick reads the first bytes of a file, so a file starting "%!" goes to the PostScript reader and one starting "%PDF-" goes to the PDF reader. The extension is a hint, and content wins when a signature matches unless a policy blocks it or the caller forces a format prefix (inferred from ImageMagick source files). The Hacker News says the same of ImageMagick, Pillow, libvips and Qt plugins (third party).

*Sources: ImageMagick documentation and source files (inferred), The Hacker News*

---

**Q: Which ImageMagick policy lines do we use as a stopgap?**

**A:** Our reading: put both lines in the policy.xml that ImageMagick actually loads. The upstream delegate line stops ImageMagick from starting the gs program. The distro-era coder line stops it from reading PS, PS2, PS3, EPS, PDF and XPS at all, which also covers builds that use Ghostscript as a library. The first line is from ImageMagick's upstream policy-secure.xml. The second comes from an older Arch Linux bug report written for an earlier Ghostscript bug, so call it a distro line, not a vendor one.

```xml
<!-- Disable execution of all delegates. -->
<policy domain="delegate" rights="none" pattern="*"/>
<policy domain="coder" rights="none" pattern="{PS,PS2,PS3,EPS,PDF,XPS}" />
```

Pattern case matters before ImageMagick 7.1.1-16: "Glob patterns are case-sensitive prior to version 7.1.1-16, so coders must be uppercase (e.g., "EPS") or use case-insensitive patterns like [Pp][Nn][Gg]." ImageMagick 6 ships its policy.xml with a different coder line commented out (rights write, for MVG, PDF, PS, SVG, TXT and XPS), not the one above, so add the coder line above deliberately. After the change, confirm with `magick identify -list policy`. Blocking is a stopgap. It breaks PDF and PostScript conversion that an app may need, and it does not help CUPS, MediaWiki or Paperless-ngx, which call Ghostscript directly.

*Sources: ImageMagick upstream policy files and security policy page, an older Arch Linux bug report (distro, not vendor), our reading*

---

**Q: Does the file extension matter?**

**A:** Not much. The researcher says files may carry an image extension (.png, .jpg, .pdf) and that EPS content reaches Ghostscript through Pillow, Imagick, libvips and Qt plugins. The Pillow source supports that: its EPS plugin is content-based (it accepts data starting "%!PS" or the DOS EPS header), is registered by default, and calls Ghostscript only when an app calls Image.open().load() on attacker bytes and the gs program is installed. So checking the extension does not protect you. To look for PostScript or PDF content under image names in stored uploads:

```bash
# Print the detected content type of stored uploads. Look for application/postscript or application/pdf under .png or .jpg names
file --mime-type <upload-dir>/*
```

*Sources: the researcher's write-up, Pillow source file (code), our reading*

---

**Q: We use CUPS. What do we check and change?**

**A:** The risk is a shared queue that accepts jobs without authentication from an untrusted network. The researcher reports an anonymous print job to a shared network queue on Debian 13 (Ghostscript 10.05.1~dfsg-1+deb13u1) ran a command as lp, one remote run plus 20 of 20 local conversions. Debian 13 is the only tested distro, and that is a researcher claim. cups-filters passes -dSAFER to Ghostscript in its filter path (inferred). Running `cupsctl` with no options prints the current settings, one name=value per line, and changes nothing. Look at _share_printers and _remote_any (our reading).

```bash
# Print the current CUPS settings (changes nothing)
cupsctl
# List the print queues
lpstat -v
```

The stopgap commands, copied from the CUPS man pages, run as root:

```bash
# Stop sharing local printers with other computers (run as root)
cupsctl --no-share-printers
# Stop accepting printing from any address (run as root)
cupsctl --no-remote-any
# Stop sharing one queue (run as root)
lpadmin -p <printer> -o printer-is-shared=false
```

Computers that print through this server stop working until you let them back in a narrower way. Requiring authentication on job submission is set through cupsd.conf policies. See the CUPS documentation. The Hacker News (third party) says requiring authentication on print queues reduces exposure.

*Sources: CUPS cupsctl and lpadmin man pages, the researcher's write-up (researcher claim), The Hacker News, cups-filters source (inferred)*

---

**Q: We run Debian. Which package is fixed?**

**A:** Debian 13 trixie: 10.05.1~dfsg-1+deb13u3 is marked fixed on the tracker, and the first fixed version is 10.05.1~dfsg-1+deb13u2 (DSA-6516-1). Debian 12 bookworm: 10.0.0~dfsg-11+deb12u9 is fixed through the security repository (DLA-4914-1, Debian LTS). The release pocket version deb12u8 is still marked vulnerable, so make sure the security repository is enabled. forky and sid: fixed in 10.08.0~dfsg-2. The tracker pages carry no advisory dates, and we give none. The Hacker News lists bookworm as "listed as vulnerable" in the researcher's survey, which matches the release pocket. The command is in the QUICK REFERENCE CARD.

*Sources: Debian security tracker, DSA-6516-1, DLA-4914-1, The Hacker News (third party)*

---

**Q: We run Red Hat, Rocky, AlmaLinux, Oracle Linux, SUSE or Amazon Linux. What now?**

**A:** There was no fixed package at the cut-off for Red Hat, SUSE Linux Enterprise or Amazon Linux. Red Hat has no record: its security data API returned "Not Found" for the CVE on 22 November, and the researcher did not establish whether current Red Hat family packages carry the fix (The Hacker News). SUSE has 21 product rows "In progress", none "Resolved", and many "Affected", and no SUSE-SU advisory was seen. Its release list shows a fixed build only for openSUSE Tumbleweed (10.08.0-5.1 or later), and SUSE Linux Enterprise builds are in QA. Amazon Linux shows ghostscript on AL2, AL2023 and AL2027 Preview as "Pending Fix". We give no upgrade command for these. Watch the vendor page, use the ImageMagick and CUPS stopgaps, and upgrade the day a fixed package appears. Say "no Red Hat statement at the cut-off" if asked.

*Sources: Red Hat security data API and CVE page, SUSE and Amazon Linux pages, The Hacker News*

---

**Q: What about Alpine, Fedora, Arch and Homebrew?**

**A:** Alpine edge has ghostscript 10.08.0-r0 (inferred fixed, it is upstream code), but the security database has no mapping for the CVE, and v3.22 and older stable branches are not fixed in the database (newest fix there is 10.05.1-r0). Fedora rawhide has 10.08.0-1.fc46 (inferred fixed, no advisory checked, stable branches not checked). Arch extra has ghostscript 10.08.0-1 (inferred fixed). Homebrew stable is 10.08.0 (inferred fixed). Judge by the installed version: for these, 10.08.0 or later is fixed.

*Sources: Alpine package and security database files, Fedora, Arch and Homebrew feeds (inferred)*

---

**Q: What about Docker images and containers?**

**A:** A container runs the Ghostscript inside its image, so patching the host changes nothing. Per the researcher and The Hacker News, a bundled copy stays vulnerable after the host updates. No official Ghostscript image exists, and images inherit distro packages (inferred). Rebuild and redeploy, and check running containers instead of assuming:

```bash
# Version inside a running container (replace <container> with its name)
docker exec <container> sh -c 'gs --version'
```

```bash
# Docker: rebuild your image so the base image and packages are fetched fresh, then redeploy
docker build --pull --no-cache -t <image> .
```

On Kubernetes, `kubectl get pods` lists what is running, and each pod's image needs the same check.

*Sources: the researcher's write-up, The Hacker News, our reading*

---

**Q: We upgraded the package. Do we still need to restart?**

**A:** Our reading: it depends on how the caller starts Ghostscript. A gs started fresh for each job picks up the new package on the next job. A long-running process that loads libgs, for example ImageMagick built with the Ghostscript library inside PHP-FPM, keeps the old copy in memory until that process restarts. On Linux, as root, this lists processes that still hold a replaced copy of the library (standard /proc usage, our reading):

```bash
# Run as root. Each line printed is /proc/<pid>/maps for one process holding a replaced libgs
grep -l 'libgs.*(deleted)' /proc/[0-9]*/maps 2>/dev/null
```

Then restart those services. Use your own unit name:

```bash
# Restart a long-running service that loads the Ghostscript library (run as root; use your own unit name)
systemctl restart <service>
```

*Sources: our reading, standard /proc usage*

---

**Q: What do we hunt for?**

**A:** No vendor publishes indicators, and Artifex, the CVE record and the researcher publish no exploit signature. These ideas are our reading. Expect false positives and treat them as leads:

- gs processes running as web or print users (lp, www-data, the Roundcube account), especially long-running ones or ones with odd parents
- A shell (sh, bash, dash) or other unexpected child process under gs or under a converter that calls gs
- Uploaded or attached files whose content type is PostScript, EPS or PDF behind an image extension (the file command above)
- The CUPS access log for jobs from unexpected addresses or with no authenticated user, on shared queues
- Web server and mail logs: first look at upload endpoints on WordPress sites with the plugins above, and at inbound mail with PostScript, EPS or PDF attachments on Roundcube hosts

```bash
# Processes running gs, with owner and parent
ps -eo user,pid,ppid,lstart,args | grep -E ' gs |/gs '
```

Absence of these signs does not prove safety, because we found no public indicators.

*Sources: CVE record, the researcher's write-up, our reading*

---

**Q: Are the public GitHub repositories safe to run for testing?**

**A:** Don't. Three repositories came back for each of the searches "CVE-2026-125396" and "upload2shell", all created on 22 November 2026. We did not open them, so what they contain is unknown, and the search can undercount. Running unknown code is a common way to get compromised, and we name none of them here. The public proof in the researcher's write-up shows a memory-write step only and fails on 10.08.0, per The Hacker News. Use the read-only commands in this document and your distro's advisory instead. If you must test, use an isolated lab VM with no route to production.

*Sources: GitHub repository search (count only, names withheld), the researcher's write-up, The Hacker News*

---

**Q: Our scanner is silent. Can we trust it?**

**A:** Not yet. We could not verify Metasploit or Nuclei coverage, and GreyNoise, Tenable, Qualys, Rapid7 and WAF vendor rules had nothing or an unreadable page (COULD NOT VERIFY). NVD still says "Awaiting Analysis". A silent scanner means little, because the CVE record is days old. A version check can also misjudge a distro backport. Judge by the version commands and the distro advisory.

*Sources: our own checks of public pages, NVD, the researcher's write-up*

---

**Q: Is the fix complete?**

**A:** For this bug, Ghostscript 10.08.0 is the fix, and the Artifex commit adds operand type checks in the font handling code (one file changed). Ken Sharp's commit message says Artifex is working to eliminate that internal step or at least minimise its use, and that this is still a work in progress. A third party quote in The Hacker News, attributed to a bug report we could not open (WEAK), has Ken Sharp calling the step "an ancient piece of code well known to be a vulnerability, but difficult to eradicate". Artifex's bug 709684 is cited by the CVE record, and its public status COULD NOT VERIFY because the tracker blocks automated fetches. This analysis has no independent test of the fix. The Hacker News says the public proof fails on 10.08.0. The same release fixes several other Ghostscript CVEs, so patch regardless.

*Sources: Artifex fix commit, Artifex Ghostscript release notes, CVE record, The Hacker News (third party)*

---

## SUCCESS CRITERIA & VERIFICATION

### You have successfully responded to Upload2Shell when:

**Technical validation checklist:**

- [ ] **All Ghostscript copies inventoried:**
    - Hosts, VMs, container images and running containers, appliances and any product that bundles Ghostscript
    - Version or distro build recorded for each, and which application feeds it files (ImageMagick, Pillow, CUPS filters, document previews, mail or wiki thumbnails)
- [ ] **All exposed hosts patched:**
    - Ghostscript 10.08.0 or later, or the distro package that your distro's advisory names (Debian 13 deb13u2 or later, Debian 12 deb12u9 or later from the security repository)
    - Where the distro has no fix yet (Ubuntu not confirmed, Red Hat no record, SUSE Linux Enterprise, Amazon Linux, Alpine stable): stopgaps in place, and a dated task to patch the day the fix ships
    - Container images rebuilt, and appliances confirmed with their suppliers in writing
- [ ] **Services that load the library restarted:** no process still holds a replaced copy
- [ ] **Application updates applied where relevant:** WordPress 7.0.4 or 6.9.7, Roundcube 1.6.20 or 1.7.5. These do not replace the Ghostscript update
- [ ] **Verification passes:**

    ```bash
    # Ghostscript version
    gs --version
    # Debian and Ubuntu: installed package and version
    dpkg -s ghostscript
    dpkg -l 'libgs*'
    # RPM distros: installed package
    rpm -q ghostscript
    # Alpine and Homebrew: installed versions
    apk info -v | grep ghostscript
    brew list --versions ghostscript
    # ImageMagick 7: active policy and delegates (expect delegate "*" with rights none if the stopgap is in place)
    magick identify -list policy
    magick -list delegate
    # CUPS: current settings and queues (changes nothing)
    cupsctl
    lpstat -v
    # Processes still holding a replaced copy of the library (run as root)
    grep -l 'libgs.*(deleted)' /proc/[0-9]*/maps 2>/dev/null
    # Processes running gs, with owner and parent
    ps -eo user,pid,ppid,lstart,args | grep -E ' gs |/gs '
    ```

- [ ] **No indicators of compromise** (see the hunting ideas in the FAQ)
- [ ] **Defense in depth:**
    - [ ] Document conversion runs under a locked-down account, container or profile with no network and no shell (our reading)
    - [ ] Apps that open untrusted images with Pillow pass only the formats they need
    - [ ] CUPS queues not shared with untrusted networks, or authentication required
    - [ ] Alerts on shells started under gs or converter processes
    - [ ] Log retention extended for forensics

---

**Operational validation checklist:**

- [ ] **Services work:** uploads convert, thumbnails render, print jobs run, previews load, and monitoring agents stay quiet
- [ ] **No new crashes, restart loops or error spikes** after the change
- [ ] **Stopgaps cleaned up:** ImageMagick policy lines and CUPS settings kept on purpose, or reverted on purpose after the fix is confirmed
- [ ] **Documentation done:** timeline, versions before and after, restart times
- [ ] **Stakeholders updated:**
    - [ ] Leadership briefed
    - [ ] Legal told whether any compromise was found
    - [ ] Insurer told the remediation is complete

---

**Compliance validation checklist:**

- [ ] **Audit trail kept:** every action timestamped, every decision explained
- [ ] **Evidence preserved** where there was any doubt
- [ ] **Breach decision documented:** legal agrees on whether notification is needed, and the evidence supports that conclusion

---

### Post-incident review checklist for the Ghostscript response

**Hold within a week of finishing:**

- [ ] **What went well:**
    - Time from the fix or CVE record to patch
    - How fast you found every Ghostscript copy
- [ ] **What needs work:**
    - Gaps in the inventory (images, appliances, bundled copies, applications that call Ghostscript indirectly)
    - Restart procedures for services that load the library
    - How many hosts waited on a distro or vendor with no fix
    - Contacts at suppliers and distros
- [ ] **Metrics captured:**
    - Time to inventory: [X hours from the day you learned of it]
    - Time to patch: [X hours]
    - Time to verified restart: [X hours]
    - Systems affected: [X]
    - Staff hours: [X]
- [ ] **Actions:**
    - Keep the Ghostscript inventory current, with the application that feeds each copy
    - Add a running-process check to the patch process
    - Rebuild images on a schedule instead of waiting for an advisory
    - Move document conversion into a contained environment

---

## ADDITIONAL RESOURCES

### Official project and CVE records

- **CVE record (CVE Program):** https://www.cve.org/CVERecord?id=CVE-2026-125396 (CNA VulnCheck, High: CVSS 3.1 7.8 and CVSS 4.0 8.5, weakness CWE-648, published 9 November 2026)
- **CVE API record (the copy we saved):** https://cveawg.mitre.org/api/cve/CVE-2026-125396 (the raw record, with the CISA ADP SSVC entry)
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2026-125396 (status "Awaiting Analysis" at the cut-off, no NVD score of its own)
- **Fix commit:** https://github.com/ArtifexSoftware/ghostpdl/commit/1484854e0c8ddfda1baa4ad4cd965b8a9790aa81 (Artifex, Ken Sharp, 2 September 2026, one file changed)
- **Ghostscript release notes:** https://ghostscript.readthedocs.io/en/latest/News.html (Version 10.08.0, 2026-09-08)
- **Ghostscript releases page:** https://ghostscript.com/releases/index.html ("The latest release is Ghostscript 10.08.0 (2026-09-08).")
- **Ghostscript usage documentation:** https://ghostscript.readthedocs.io/en/latest/Use.html (what -dSAFER does, and the -dNOSAFER warning)

### Government and CERT advisories

- **CISA:** the CVE is not in the KEV catalog at the cut-off (0 matches in a feed of 1790 entries, released 20 November 2026): https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json. CISA's SSVC entry in the CVE record (10 November 2026): Exploitation none, Automatable no, Technical Impact total
- **National CERT advisories:** we found none for this CVE in our sources

### Research and press

- **The Hacker News (22 November 2026):** https://thehackernews.com/2026/11/researchers-demonstrate-ghostscript.html (the only press article we saw on this CVE. Third party)
- **oss-security, reply archived 22 November:** https://www.openwall.com/lists/oss-security/2026/11/22/1 (the reply the CVE record links, posted 21 November 2026 at 19:59 UTC)
- **oss-security, announcement:** https://www.openwall.com/lists/oss-security/2026/11/21/2 (listed in the 21 November day index as message 2. The page itself was not saved)
- **The researcher's write-up:** linked from the CVE record. We cite it by description only and give no web address. It is dated 21 November 2026 and is a third party source. Each claim from it in this document is attributed

### Scoring and tracking feeds

- **EPSS API:** https://api.first.org/data/v1/epss?cve=CVE-2026-125396 (0.00164, percentile 0.056, 21 November 2026. A model score, not evidence of safety)
- **CISA KEV catalog feed:** see the CISA entry above
- **Exploit tracking:** GreyNoise, Tenable, Qualys, Rapid7, Metasploit, Nuclei and WAF vendor rules: nothing found or page unreadable (COULD NOT VERIFY). Treat GitHub repositories that claim to be proofs of concept as unreviewed and untrusted

### Vendor and distro advisories

- **Debian tracker:** https://security-tracker.debian.org/tracker/CVE-2026-125396 (trixie 10.05.1~dfsg-1+deb13u3 fixed, first fixed deb13u2; bookworm deb12u9 fixed in the security repository, deb12u8 still vulnerable; forky and sid 10.08.0~dfsg-2)
- **Debian DSA-6516-1:** https://security-tracker.debian.org/tracker/DSA-6516-1 (lists this CVE and CVE-2026-39919)
- **Debian DLA-4914-1:** https://security-tracker.debian.org/tracker/DLA-4914-1 (Debian LTS for bookworm; lists several Ghostscript CVEs)
- **Ubuntu CVE page:** https://ubuntu.com/security/CVE-2026-125396 (priority Medium, "Needs evaluation" on all seven releases, last updated 18 November 2026)
- **Ubuntu USN-8949-1:** https://ubuntu.com/security/notices/USN-8949-1 (21 October 2026, "Ghostscript vulnerabilities". Fixed versions: 26.10 10.07.1~dfsg-1ubuntu2.1; 26.04 10.06.0~dfsg-3ubuntu1.2; 24.04 10.02.1~dfsg1-0ubuntu7.10; 22.04 9.55.0~dfsg1-0ubuntu5.15; 20.04 9.50~dfsg-5ubuntu4.15+esm3 (Ubuntu Pro); 18.04 9.26~dfsg+0-0ubuntu0.18.04.18+esm6 (Ubuntu Pro); 16.04 9.26~dfsg+0-0ubuntu0.16.04.14+esm11 (Ubuntu Pro). These are for the notice, not confirmed for this CVE)
- **SUSE:** https://www.suse.com/security/cve/CVE-2026-125396.html (rated important, 21 product rows "In progress", none "Resolved". The release list shows openSUSE Tumbleweed fixed at 10.08.0-5.1 or later and SUSE Linux Enterprise builds "in QA")
- **Amazon Linux:** https://explore.alas.aws.amazon.com/CVE-2026-125396.html (Important, CVSS 7.8, ghostscript on AL2, AL2023 and AL2027 Preview "Pending Fix")
- **Red Hat:** no record for this CVE at the cut-off
- **Alpine, Fedora, Arch, Homebrew:** see the FAQ for the builds we inferred are fixed (no URLs listed here)

### Application advisories

- **WordPress advisory:** https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8vr3-7mxf-gx8w (CVE-2026-65640, needs an Author level user or higher)
- **WordPress 7.0.4 release:** https://wordpress.org/news/2026/08/wordpress-7-0-4-release/ (the release post linked from the CVE-2026-65640 record, which says the fix was backported to all branches back to 4.7)
- **Roundcube advisory:** https://github.com/advisories/GHSA-j8wg-2q5h-m4xq (CVE-2026-114727, hardening in 1.6.20 and 1.7.5, does not name Ghostscript)
- **Roundcube news:** https://roundcube.net/news/2026/10/19/security-updates-1.6.20-and-1.7.5 (19 October 2026)

### Tool documentation for stopgaps

- **ImageMagick security policy:** https://imagemagick.org/security-policy/ (how to disable delegates and confirm the active policy)
- **ImageMagick policy-secure.xml, upstream:** https://raw.githubusercontent.com/ImageMagick/ImageMagick/main/config/policy-secure.xml (the delegate line we cite)
- **Arch bug report (distro-era policy line):** https://bugs.archlinux.org/task/59778 (an older distro bug report, not upstream ImageMagick text)
- **CUPS cupsctl man page:** https://openprinting.github.io/cups/doc/man-cupsctl.html
- **CUPS lpadmin man page:** https://openprinting.github.io/cups/doc/man-lpadmin.html
- **Pillow Image module docs:** https://pillow.readthedocs.io/en/stable/reference/Image.html (the formats argument of Image.open())

### Emergency support contacts

- **Suppliers of appliances and panels:** the supplier's security contact (not an incident hotline)
- **CISA:** report@cisa.gov or +1 888-282-0870
- **FBI Internet Crime Complaint Center (IC3):** report online (US)
- **CERT-In (India):** incident@cert-in.org.in or 1800-11-4949
- **NCSC-UK:** its online incident reporting service
- **Your hosting provider's security contact, your Linux distributor's security team and your incident response retainer**

---

## QUICK REFERENCE CARD

### Print and post this card for Upload2Shell

```
===============================================================
  UPLOAD2SHELL (CVE-2026-125396): GHOSTSCRIPT -dSAFER BYPASS
  CVE record: High | CVSS 3.1: 7.8 | CVSS 4.0: 8.5
  CRITICAL tier below is our reading, not the CVE's rating
===============================================================

AFFECTED:
  Ghostscript before 10.08.0 (CVE record). No start version
  is given. Separate copies bundled in images and apps count

FIXED IN:
  Ghostscript 10.08.0 (8 September 2026)
  Distro builds keep old numbers: Debian 13 deb13u2 or later,
  Debian 12 deb12u9 or later (security repository)
  Ubuntu: NOT CONFIRMED. Red Hat: no record. SUSE: mostly open.
  SUSE Tumbleweed: fixed. SUSE Enterprise: in QA.
  Amazon Linux: pending. Alpine stable: no fixed build

NOT A MITIGATION:
  -dSAFER (this bug gets around it). Do not use -dNOSAFER either

---------------------------------------------------------------
YOU ARE EXPOSED WHEN ALL OF THESE ARE TRUE:
---------------------------------------------------------------

  1. An affected Ghostscript is installed (host or image)
  2. An application hands it files: ImageMagick, Pillow EPS
     loading, CUPS filters, document previews, mail or wiki
     thumbnails
  3. An untrusted PostScript, EPS or PDF file can reach that
     application, even behind an image extension

  No login needed for the CRITICAL tier (our reading):
  shared CUPS queues, public upload forms, inbound mail

---------------------------------------------------------------
IMMEDIATE ACTIONS:
---------------------------------------------------------------

1. CHECK (1 minute):
   # Ghostscript version
   gs --version
   # Debian and Ubuntu: installed package and version
   dpkg -s ghostscript
   dpkg -l 'libgs*'
   # RPM distros: installed package
   rpm -q ghostscript
   # Alpine: installed package with its version
   apk info -v | grep ghostscript
   # Homebrew: installed version
   brew list --versions ghostscript
   # Containers: version inside a running container
   docker exec <container> sh -c 'gs --version'

2. PATCH (hosts that take outside files first):
   # Debian 13 and 12 (Debian 12 needs the bookworm-security
   # repository enabled), Ubuntu 24.04 and later (run as root)
   apt-get update
   apt-get install --only-upgrade ghostscript libgs10 libgs10-common
   # Ubuntu 22.04 and older (run as root). Ubuntu has not
   # confirmed that its builds fix this CVE
   apt-get update
   apt-get install --only-upgrade ghostscript libgs9 libgs9-common
   # Alpine edge only (run as root). Alpine stable branches had
   # no fixed build at the cut-off
   apk update
   apk upgrade ghostscript
   # Arch (run as root). Arch supports full upgrades only
   pacman -Syu
   # Homebrew
   brew upgrade ghostscript
   # Docker: rebuild your image so the base image and packages
   # are fetched fresh, then redeploy
   docker build --pull --no-cache -t <image> .
   # Restart long-running services that load the Ghostscript
   # library, for example PHP-FPM with Imagick (run as root;
   # use your own unit name)
   systemctl restart <service>
   Red Hat, SUSE Linux Enterprise and Amazon Linux: no
   fixed package at the cut-off. Use the stopgaps below and watch the vendor page

3. CAN'T PATCH TODAY? Stopgaps, not fixes:
   ImageMagick: put both lines in the policy.xml it loads,
   then confirm with: magick identify -list policy
     <policy domain="delegate" rights="none" pattern="*"/>
     <policy domain="coder" rights="none" pattern="{PS,PS2,PS3,EPS,PDF,XPS}" />
   CUPS (run as root): stop sharing with untrusted networks
     cupsctl --no-share-printers
     cupsctl --no-remote-any
     lpadmin -p <printer> -o printer-is-shared=false
   Pillow: open untrusted images with only the formats the
   app needs, so EPS is never tried
   Contain conversion: locked-down account, no network, no
   shell (our reading)

4. ALSO UPDATE THE APPLICATIONS (separate fixes, not a
   substitute): WordPress 7.0.4 or 6.9.7, Roundcube 1.6.20
   or 1.7.5

---------------------------------------------------------------
WHAT TO WATCH (we found no published indicators of compromise):
---------------------------------------------------------------

  gs processes running as lp, www-data or the mail account
  A shell or other unexpected child under gs or a converter
  PostScript or PDF content under .png or .jpg names:
    file --mime-type <upload-dir>/*
  CUPS jobs from unexpected addresses or with no user
  Clean logs prove little: no known fingerprint exists

---------------------------------------------------------------
THREAT LEVEL (22 November 2026, 12:30 UTC):
---------------------------------------------------------------

  No attacks reported at the cut-off (The Hacker News, third
  party). CISA SSVC: Exploitation none, Automatable no,
  Technical Impact total
  Not in CISA KEV. EPSS 0.00164 (percentile 0.056)
  Public proof is partial: a memory-write step only (the
  researcher's write-up). Do not run repositories named
  after the CVE

---------------------------------------------------------------
IF COMPROMISED:
---------------------------------------------------------------

  1. Isolate the host (keep it running for evidence)
  2. Capture the process list, network connections and logs
     BEFORE any restart or patch. Preserve logs. Do NOT
     delete anything
  3. Rotate every secret the account running Ghostscript
     could read
  4. Bring in incident response, legal and your insurer
  5. Contact: [Your security team / CISO]

---------------------------------------------------------------
MORE INFORMATION:
---------------------------------------------------------------

  CVE record: CVE-2026-125396 (CNA VulnCheck)
  Fix:        Artifex commit 1484854e, Ghostscript 10.08.0
  Distros:    the CVE page of your distribution (see
              ADDITIONAL RESOURCES)

  Emergency Support: [Your IT Security Contact]
  Phone: [Phone Number]
  Email: [Email Address]

===============================================================
   A fixed package on disk with the old process still running
                  is not fixed. Patch, then restart.
===============================================================

Document Version: 1.0
Last Updated: 22 November 2026
Data cut-off: 22 November 2026, 12:30 UTC
Classification: TLP:CLEAR, public distribution
```

*Sources: CVE record, Artifex Ghostscript release notes, Debian, Ubuntu, SUSE and Amazon Linux pages, ImageMagick and CUPS documentation, WordPress and Roundcube advisories. Details are in the sections above.*

---

## FINAL RECOMMENDATIONS

### The bottom line on Upload2Shell

**If your hosts run Ghostscript 10.08.0 or later, or your distro's fixed package, and services that load the library have restarted:**

- You have the upstream fix for this CVE (this analysis has not tested it independently)
- Keep the detection on: shells started under gs or converters, PostScript or PDF content under image names
- Check images and appliances separately, because each carries its own copy

**If untrusted files reach an affected Ghostscript with no login (shared CUPS queue, public upload form, inbound mail with ImageMagick):**

- Patch today where a fixed package exists. This is the CRITICAL tier, our reading, not the CVE's rating
- Where no fix exists yet, block ImageMagick delegates and stop sharing queues with untrusted networks until it does
- Check logs and process history as far back as retention allows

**If you run Debian:**

- Debian 13 deb13u2 or later and Debian 12 deb12u9 or later (security repository) carry the fix. Install, then restart services that load the library

**If you run Ubuntu:**

- Ubuntu has not confirmed a fix for this CVE. Apply the stopgaps, install the USN-8949-1 package for your release (not confirmed for this bug) and watch the Ubuntu CVE page

**If you run Red Hat family, SUSE Linux Enterprise, Amazon Linux or Alpine stable:**

- No fixed package at the cut-off. Use the stopgaps and update the day a fixed package appears

**If you run Docker images, appliances or bundled apps:**

- Rebuild or ask the supplier in writing. Patching the host doesn't change an image

**If you only updated WordPress or Roundcube:**

- Those are separate application fixes, not the Ghostscript fix (the researcher links both to this chain). Patch Ghostscript too

**If you don't know where Ghostscript runs:**

- Find out in the next two hours. Start with the version commands in the QUICK REFERENCE CARD

### Takeaway for leadership

CVE-2026-125396 is a Ghostscript bug that can run commands as the account running Ghostscript, and the danger comes from what sits in front of it. Ghostscript is called by print queues, mail clients, upload forms and document previews, often without the application calling it directly. The CVE record rates it High (7.8 and 8.5) and treats it as a local file processor. We rate it CRITICAL where an outsider can reach an affected copy with no login, and that tier is our reading. The researcher reports command execution in the setups the researcher tested, and none of that is independently confirmed. No attacks were reported at the cut-off. The fix is 11 weeks old: the news is the disclosure, not a new patch. Distro coverage is uneven. Debian has fixed packages, Ubuntu has not confirmed one, and Red Hat, SUSE and Amazon Linux had none at the cut-off. -dSAFER does not help, because the bug gets around it. Updating WordPress or Roundcube does not help on its own, because those are separate application fixes.

Use the incident to fix four things:

1. Know every place Ghostscript runs, including images and appliances, and which application feeds each one
2. Know which of those take files from people you do not control
3. Run document conversion in a contained environment with no network and no shell
4. Treat the service restart as part of patching, and check that the running process is the fixed one

### Remember

- Ghostscript before 10.08.0 is affected, and distro builds keep old numbers, so judge them by the distro advisory
- -dSAFER is not a mitigation: the bug gets around it
- Ubuntu is not confirmed fixed, and Red Hat has no record
- WordPress and Roundcube fixes are separate application fixes and do not replace the Ghostscript fix
- Separate copies in images and apps stay vulnerable after the host updates
- The CVE is High. The CRITICAL tier is our reading
- No attacks reported at the cut-off. That can change quickly
- Clean logs prove little: we found no published indicators of compromise
- Don't run the public repositories named after the CVE

**Patch Ghostscript today. Restart the services that load it.**

---

**Document Version:** 1.0
**Last Updated:** 22 November 2026
**Data cut-off:** 22 November 2026, 12:30 UTC
**Classification:** TLP:CLEAR, public distribution
**Prepared by:** 0xDTC (TheSecureLancer)

Facts in this document come from Artifex and the Ghostscript project, the CVE record, distro and vendor advisories, application advisories, mailing list posts, the researcher's write-up, tool documentation and press coverage listed above. Where those sources disagree, the document says so.
