# Enterprise PS Scripts

`Enterprise-PS-Scripts` is a repository of useful PowerShell scripts and workflows for junior administrators who need practical tools they can read, run, and learn from.

The goal is simple:

- Help newer admins automate repetitive work
- Provide examples that are safer than one-off copy/paste scripts
- Keep scripts readable, documented, and usable in real Windows environments
- Build a library of admin tools that can grow over time

## Who This Repo Is For

This repo is intended for:

- Junior Windows administrators
- Help desk and operations staff growing into server administration
- Sysadmins who want reusable PowerShell examples
- Teams that want practical scripts with clear documentation

## What You Will Find Here

This repository is meant to collect useful scripts for common enterprise administration tasks, such as:

- Security and vulnerability detection
- Remediation workflows
- Reporting and inventory collection
- Server maintenance tasks
- Operational troubleshooting utilities

Some scripts are simple single-purpose tools. Others are larger, safer workflows with configuration files, reporting, and rollback guidance.

## Current Projects

### MSXML4 Remediation

PowerShell 5.1 detection, reporting, and optional remediation workflow for Microsoft MSXML 4 exposure across Windows servers.

Project files:

- [`MSXML4_Remediation`](./MSXML4_Remediation/)
- [`Project README`](./MSXML4_Remediation/README.md)
- [`Invoke-MSXML4Remediation.ps1`](./MSXML4_Remediation/Invoke-MSXML4Remediation.ps1)

Highlights:

- Audit-first design
- Dry-run and preview support
- No-WinRM support
- Quarantine-first remediation
- Rollback metadata and reporting

### Check Current Patch Level

PowerShell 5.1 server update audit workflow for checking installed updates, connectivity, and reporting patch status across Windows servers.

Project files:

- [`Check_Current_PatchLevel`](./Check_Current_PatchLevel/)
- [`Project README`](./Check_Current_PatchLevel/README.md)
- [`Get-ServerUpdateAudit.ps1`](./Check_Current_PatchLevel/Get-ServerUpdateAudit.ps1)

Highlights:

- Patch and update inventory reporting
- Dry-run and connectivity-only validation
- WinRM and no-WinRM compatible collection paths
- Reusable reporting module
- Configuration-driven server targeting
## Design Principles

Scripts in this repo should aim to be:

- Safe by default
- Useful in real admin environments
- Compatible with Windows PowerShell 5.1 when possible
- Well documented
- Understandable by someone still learning

That means no fake-magic delete scripts, no hidden credentials, and no mystery behavior.

## How To Use This Repo

1. Read the project README before running a script.
2. Review the configuration file if the project uses one.
3. Start with audit-only or dry-run mode whenever available.
4. Test in a safe environment before broad production use.
5. Use the scripts as both tools and learning material.

## Notes

- This repository may include scripts in different stages of maturity.
- Always review code before running it in your environment.
- Enterprise environments differ, so you should validate permissions, remoting, firewall access, and change-control requirements before use.

## Roadmap

Over time, this repo can grow into a collection of practical scripts for:

- Patch auditing
- Certificate inspection
- Server reboot orchestration
- Compliance checks
- Inventory and reporting

## License and Internal Review

If you plan to use a script in production, review it with your team’s normal operational and security process first.
