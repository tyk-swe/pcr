# Security policy

PacketcraftR parses capture files and packets that may come from people you do not trust, and its live features can send and capture real traffic under a fail-closed policy. We take reports about both sides seriously and we would rather hear about a problem privately first so a fix can ship before working exploit details are public.

## Supported versions

Security fixes land on the `main` branch and ship in the next release. The latest published release and `main` are supported. Older releases, including earlier beta releases in the same series, are not supported and the fix for those users is to upgrade to the latest release.

## Reporting a vulnerability

Do not open a public issue or pull request for a suspected vulnerability.

Email mail@mail.tyk.sh, or use the Report a vulnerability button on the repository Security tab, which opens a private report that only the maintainer can see.

Include the release version or commit you tested, your platform and which feature build you used, the smallest input file or command line that reproduces the problem, and what an attacker gains from it. A crashing capture or document file is enough on its own and you do not need to develop it further before reporting.

We will acknowledge your report, investigate it, and coordinate a disclosure date with you once a fix is ready. We are happy to credit reporters in the release notes unless you would rather stay anonymous.

## Scope

Reports we especially want include the following.

- A capture file, packet, packet document, indicator or rules document, or display filter that crashes the tool, overflows the stack, or makes it use memory or time far beyond its configured limits.
- Any memory safety problem in the native platform code that handles capture devices, raw sockets, routes, or interface enumeration.
- Any way for live traffic to leave the machine, or for name resolution or capture to start, before the traffic policy has authorized the destination and the packet and byte budgets.
- Any way for the TLS audit to present an untrusted, expired, or wrongly named certificate as verified.
- Any output path that follows a swapped symlink or directory, overwrites a file it promised not to clobber, or lets captured bytes inject terminal escape sequences into human-readable output.
- Any weakness in the repository dependency, CI, or release setup that could put modified code or binaries in front of users.

The following are outside the scope of this policy.

- Using the send, scan, exchange, or capture commands against systems you are not authorized to test. Those commands exist for authorized diagnostics and protocol testing, and the policy defaults are there to prevent accidents rather than to make an authorized operator harmless.
- Resource use that only happens because an operator raised the documented limits on their own machine.
- Vulnerabilities in the operating system, libpcap, or Npcap themselves. Report those to their own projects, and tell us as well when our use of them is what triggers the problem.

## Guarantees and known platform limits

Socket audits are admitted once, before any connection, for their whole traffic. A TLS or HTTPS audit reserves one connection plus one traffic unit for every TLS transport step and its whole ciphertext byte ceiling, because the TLS transport refuses any read, write, or flush attempt past its step limit. A plain HTTP audit reserves one connection and one request message. Traffic units count connections and socket messages, not IP packets.

PacketcraftR stages every file it writes inside the destination's parent directory and publishes it atomically. On Unix the parent is opened once before any input is read, and every later check, write, publication, and cleanup step is relative to that open directory, so a symlink swap or a renamed and replaced parent or ancestor cannot redirect output. On Linux the staged file has no name until it is linked into place. On other Unix systems, and on Linux filesystems without `O_TMPFILE` or procfs, the staged file has a hidden random name. Publication is refused if that name no longer refers to the file PacketcraftR wrote, and a substitution that races the atomic publish makes the command fail instead of leaving the substitute in place. On Windows the parent directory is held open so it cannot be renamed or deleted while output is staged, but replacing an ancestor directory or substituting the staged file there is not prevented, and this path has not yet been verified on a native Windows host. Attackers running as the same user, and filesystems that lack the required primitives, are out of scope. Missing primitives cause an error rather than a weaker publication. Atomic publication is not crash durability.

On Unix, PacketcraftR waits for data from stdin, FIFOs, sockets, and character devices in short slices, so `--max-duration-ms` and the first Ctrl-C stop an input that never sends data, including a FIFO that never gets a writer. On Windows, reads from anonymous-pipe stdin and named pipes still block, because the standard library has no safe readiness wait there, and only the second Ctrl-C ends such a stalled read. Reads of regular files, including files on network filesystems, cannot be interrupted while a single read is in progress. If another process reads the same stdin pipe, it can drain the data between the readiness check and the read, and that read can then block.

## Running PacketcraftR with least privilege

Offline work such as building packets, reading captures, and running analysis needs no elevation at all. Run those commands as your regular user, especially on captures and documents that came from someone else.

Live capture and raw packet transmission need whatever permission your operating system requires for those operations. Grant only the capture or raw socket permission the feature needs where your operating system offers a narrower grant than full administrator or root access, and return to an unprivileged shell for analysis afterward. Do not make the binary setuid to work around a permission prompt.

Treat every capture, packet document, and rules or indicators file from another person as untrusted input. The parsers are bounded and fuzzed with that assumption, and the safest workflow is still to open such files without elevation and to keep the default limits unless you have a reason to raise them.
