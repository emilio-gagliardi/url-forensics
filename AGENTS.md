# Defensive URL Forensics agent instructions

- Work only with the code in this dedicated repository. Do not fetch or mount other repos.
- Do not add secrets, customer data, SSH keys or service credentials.
- Do not run suspicious target URLs during setup or CI.
- Before any live inspection, require that the user explicitly supplies the URL and chooses inspection mode.
- Only run a live probe in a disposable environment with no private VPN, Docker socket, privileged mounts, or credentials.
- Do not run downloaded files, macros, installers, shell scripts, or browser extensions supplied by a target.
- Do not circumvent CAPTCHA, access controls, authentication or rate limiting.
- Do not submit forms or credentials. Do not follow links other than automatic redirects.
- Save reports to a new directory; store reports outside Git.
- The browser route guard is advisory; VM/firewall egress controls are required to enforce private-IP denial.
- First run `python -m unittest discover -s tests -v`.
