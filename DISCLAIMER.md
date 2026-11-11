# Responsible Use and Disclaimer

OniOps is a security testing tool. I built it to help people learn offensive
security, test their own labs, and run assessments they are authorized to
perform. Please read this before using it.

## Use it legally and with permission

Only run OniOps against systems that **you own**, or that you have **explicit
written permission** to test (for example, a signed scope or rules of
engagement from the system owner). Scanning or attacking systems without
permission is illegal in most countries, even if no damage is done.

If you are not sure whether you are allowed to test something, do not test it.

## You are responsible for how you use it

OniOps is provided **"as is", without warranty of any kind**. Under sections 7
and 8 of the [Apache-2.0 license](LICENSE), the author is not liable for any
damages arising from its use.

By using, copying, modifying, or distributing OniOps, you agree that:

- **You alone are responsible** for your actions with OniOps, for obtaining
  proper authorization, and for following all laws and regulations that apply
  to you.
- **The author does not condone, and is not responsible or liable for, any
  misuse of OniOps.** This includes unauthorized access, attacks against any
  person, company, or organization, disruption of services, loss or damage of
  data, and any other harm or legal consequence resulting from its use.
- **The author is not responsible for modified versions, forks, or
  redistributions** made by anyone else — including versions that remove,
  weaken, or bypass OniOps's safety controls. Whoever changes or redistributes
  OniOps is responsible for those changes and for how they are used. The
  [Apache-2.0 license](LICENSE) also requires modified files to carry a notice
  that they were changed (section 4(b)), and the [`NOTICE`](NOTICE) file,
  which includes this disclaimer, must be kept with every copy (section 4(d)).

## Safety features are aids, not guarantees

OniOps ships with a scope allow-list, a non-destructive guard, and authentication
options that are on by default. They help prevent mistakes, but they are not a
guarantee that nothing can go wrong, and they are not a substitute for having
permission.

## Reporting problems

If you find a security issue in OniOps itself, please report it privately — see
[`SECURITY.md`](SECURITY.md).
