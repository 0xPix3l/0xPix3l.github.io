---
title: "Do You Really Understand Kerberos Delegation?"
date: 2026-03-27
permalink: /Active-Directory/Delegation/
categories: [Active Directory, Delegation]
tags: [Active Directory]
math: true
mermaid: true
image:
  path: /assets/img/Delegation/delegation.jpg
---

---

Hello fellow packet enjoyers and delegation survivors,

Today we’re (deep) diving into one of those Active Directory “features” that sounds simple on paper but quickly turns into a full-blown existential crisis once you actually try to understand it.

You’ve probably seen the buzzwords thrown around like
S4U2Self, S4U2Proxy, RBCD, forwardable tickets…
and at some point you just nod and pretend it makes sense.
![image](/assets/img/Delegation/brainfuck.png)
_image from @theluemmel_
well… it doesn’t



So in this post, we’re going to tear this thing apart properly.
Not just “what it does”, but what the KDC is actually doing,  how tickets are being forged, modified, and forwarded, and most importantly… what this looks like on the wire


This post is mainly for two reasons:

1. Beacuse why not
2. To help me understand what the hell is going on for this topic a little more in detail


If you’ve ever:
- blindly run `Rubeus s4u` and hoped for the best
- been confused why you need a forwardable ticket
- or didn’t understand why delegation sometimes works and sometimes doesn’t

this post is for you.

--- 

## Content

We’ll walk through:

- Unconstrained Delegation
- Constrained Delegation (with and without protocol transition)
- Resource-Based Constrained Delegation



### Disclaimer 
Before we go any further, go grab a cup of coffee… or two.

This is not one of those 5 minute read posts where you skim a few diagrams and call it a day.
We’re going deep into the weeds here.. packets, ticket flags, KDC logic, weird edge cases, and the kind of stuff that makes you question your life choices at 3AM.

Now let’s break it.

---



## Prompts


<!-- markdownlint-disable -->
> An example showing the `tip` type prompt.
{: .prompt-tip }

> An example showing the `info` type prompt.
{: .prompt-info }

> An example showing the `warning` type prompt.
{: .prompt-warning }

> An example showing the `danger` type prompt.
{: .prompt-danger }
<!-- markdownlint-restore -->