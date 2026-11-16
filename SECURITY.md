# Security Policy

## Reporting a vulnerability in wpguard

Please report security issues privately rather than in a public issue or a
discussion. A report that contains a working exploit against wpguard itself
should be sent as a private advisory on the repository, or by email to the
maintainer.

Include:

- what the issue is,
- the version or commit you tested,
- the steps to reproduce it,
- the impact you believe it has.

You should get an acknowledgement within a week. Fixes ship in the next
release, and the advisory is published once a fixed version is available.

## What is in scope

wpguard parses untrusted PHP. The interesting attack surface is therefore:

- a crafted PHP file that makes wpguard panic, hang, or read files it should
  not,
- a crafted PHP file that makes wpguard report a finding which is not there,
  in a way that hides a real finding,
- anything that causes wpguard to make a network request,
- path traversal in the file walking or in the reported paths.

## What is out of scope

- wpguard missing a vulnerability in the code it analyses. That is the job of
  the rules, not a vulnerability in the tool. Open a feature request instead.
- wpguard reporting a false positive. That is a bug, and it is welcome as a
  public issue. Please include the snippet that triggers it.
- Denial of service by pointing wpguard at a genuinely enormous directory. The
  tool is meant for plugins, not for whole distributions.

## Guarantees

- wpguard never executes the PHP it analyses.
- wpguard never makes a network request.
- wpguard never writes to the code it analyses. The only file it writes is the
  one you explicitly ask for with `--output` or `--write-baseline`.
