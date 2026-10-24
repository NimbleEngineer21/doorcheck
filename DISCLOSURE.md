# Problems found in other people's projects

Doorcheck looks at code written by volunteers who share it for free. Finding a
problem in their work and posting it publicly before they can fix it puts their
users at risk and treats them unfairly. So Doorcheck tells the maintainer first,
privately, and only talks about it in public once it is fixed or the deadline
below has passed.

## Who is told, in order

1. The project's own private channel: GitHub private vulnerability reporting
   if it's turned on, otherwise the security contact in its `SECURITY.md`.
2. The maintainer's email, if there's no private channel.
3. If there's no answer after 30 days, or the problem is being exploited, the
   Home Assistant Marketplace maintainers, who can stop offering the code.

Every message is written by a person who has checked the problem by hand, not
generated and sent by a tool.

## How long it stays private

90 days from the first message, or until a fixed release ships, whichever comes
first. The deadline can move if the maintainer is working on a fix and asks for
more time. If the problem is already being exploited, users are warned sooner,
without the details an attacker would need.

## What stays out of public view until then

- The benchmark corpus in this repository only holds bugs whose fix has shipped.
  Cases still under embargo live in a private corpus outside the repository.
- Pull requests, CI output, the results feed and posts don't name a project
  with an unfixed problem, or give its file and line.
- Scans of projects shared on forums or Reddit that turn up a problem follow the
  same steps. Results posted publicly as evidence are counts, not names.

## Disagreements

A maintainer who thinks a finding is wrong can say so, privately or in public.
If they're right, the rule that produced it gets fixed, and that fix comes with
a test case.
