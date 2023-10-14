+++
author = "Dylan"
title = "Running a CTF that Outlasts a Bag of Popcorn"
date = "2023-09-11"
description = "Tales and experiences from running PatriotCTF 2023."
tags = [
    "infrastructure","challenge creation","docker"
]
+++

My tales and experiences from running PatriotCTF 2023.
<!--more-->

# Table of content
1. [Foreword](#foreword)
2. [Hack-proof Hacking Challenges](#containerization)
3. [Intended Unitendeds](#integrity)
4. [The Final Hour](#popcorn)
5. [Postface](#postface)

## Foreword
<a name="foreword"></a>
Running a CTF is hard. Very hard. It involves a lot of moving parts and interacting with technology in a way that is considerate and thorough, even if you are not familiar with it.
Lot's can go wrong at every step and frequently a lot does. So in acknowledgement of this, I decided to upload this, to make sure that the next organizers of PatriotCTF and their successors, and their successor's successors would have some reference to the issues their not-so-distant ancestors encountered.

For context, last weekend was Mason Competitive Cyber's annual capture-the-flag competition, PatriotCTF and it was our turn to run it.
Prior to this event, no one on the active exec board had any substancial experience with infrastructure or sysops. Considering this, the event ran extremly well with very few hiccups. PCTF was hosted on AWS using CTFd. Our infrastructure was staged on two servers, one which was hosting the main CTFd instance and one hosting challenge remotes (c6a.2xlarge). Cloudflare was used for a reverse proxy as well as providing a subdomain for the challenge remotes.
We also had help from a very talented alumni in filling lacking categories, warm thanks to <a href="https://github.com/ChrisTheCoolHut">Christopher Roberts</a> for coming in clutch with two awesome vm rev challenges and an awesome ARM pwn.


## Containerization
<a name="containerization"></a>
Firstly and very importantly, all remotes were containerized. This was done using docker, for the pwn challenges we used <a href="https://github.com/redpwn/jail">**redpwn**</a> jail and for other remotes we mostly relied on **xinetd**. Redpwn/jail is an nsjail docker image for CTF pwnables, which allows for isolated, forked and highly configurable containers for pwnables. This is done by mounting the given challenge binary into /srv/app/run, which is used in the nsjail, which then in turn is in the docker. Besides the fact that it is jailed, the service itself is similar to that of xinetd and every connection has its own process that is forked and killed upon disconnection. It is important to note that best practice is to pull from an actual os image (eg. ubuntu) and copy it into root directory as the base redpwn has no filesystem and is very minimal. Redpwn also allows for configuring how the jail is handled using environment variables that can be set in the dockerfile. Using these variables we can configure how connections are handled and even the syscalls the pwnable is allowed to make. For instance, `JAIL_TIME` can be useful to limit the connections by setting a timeout which will kill the connection if it is exceeded. This could be set relatively low (like 60 seconds for the example I will show) assuming this is meant to be solved with a developed exploit. I did opt in however, to make the `JAIL_TIME` not unreasonably low, as the user should be able to explore the program on the remote somewhat if they so choose. The following is an example of a redpwn Dockerfile for the **bookshelfv2** challenge. 
```docker
FROM pwn.red/jail

ENV JAIL_TIME=60
ENV JAIL_CONNS_PER_IP=10
ENV JAIL_PORT=8989
ENV JAIL_SYSCALLS=accept,accept4,...

COPY --from=ubuntu / /srv

COPY bookshelf /srv/app/run
COPY flag.txt /srv/app/flag.txt
```
It really is as simple as that. More examples can be found in the <a href="https://github.com/MasonCompetitiveCyber/PatriotCTF2023/tree/main">challenge repo</a>.

## Challenge Integrity
<a name="integrity"></a>
All challenges should be extensivley tested. Hard ones however, especially so. This is because if there is a way to cheese a tough challenge, it puts the integrity of the entire scoring system at stake. Organizers should make it an effort to have anyone (who is not the author of said challenge) blindly solve hard challenges in a testing environment in an attempt to find unintendeds as they are more capable of doing so than challenge authors who know and expect the intended path. An unintended solution isn't necesarily the end of the world, unless it is significantly easier than the intended solution. Softshell, my hard heap grooming challenge, had an intended solution of transforming an arbritrary free into an arbritrary write. The arbritrary free was subtle and hard to point out as it resulted from a simple difference in how the program calculated a command list and how it calculated its size.
<img src="/assets/2023-09-11/3.png"/>

And because the program has functionality that when deleting the last argument, frees based on argslen (which can be larger than the actual list of arguments), we have an arbritrary free. The vulnerability itself was hard to spot, but the main reason for the difficulty rating was actually exploiting this bug. The intended solution was to groom the heap with more command structs and create a UAF on a future command's tag list and then using the edit tag command to obtain a write-what-where. The main goal was to find one bug and turn it into a more useful one. However, there was an unintended UAF in the command arguments, which allowed one to deviate from the difficult intended path by bypassing the command check and solve it without the need for any of the primitives. This allowed for a much easier (and overall while not baby, still easy) solution to an "insane" rated challenge. Luckily, a good lot of competitors did actually solve the challenge the intended way and if you're curious about it, a good writeup exists <a href="https://ctf.krloer.com/writeups/patriotctf/softshell/">here.</a> However, the reasoning behind the amount of solves the challenge got, which was initially puzzling to me, is now clear. Of course softshell is a long challenge with lots of heap management and therefore it is harder to analyze and test all the coverage because of its complexity and moving parts.

## Break in case of server issues
<a name="popcorn"></a>
It's Friday afternoon and everything was set and going swimingly until, 45 minutes before the competition was set to begin and the CTFd was supposed to open, the following happened.
<img src="/assets/2023-09-11/1.png"/>

The number one rule for hosting CTFs is if nothing is wrong, that just means you don't know what is wrong. Something will go wrong and the simple reason behind that is because there is simply too much to properly account for. There can be no reasonable amount of people to expect to exceptionally know the intrinsic details of all the pieces of your infrastructure. So a good doomsday plan to live by is instead of fixing everything and expecting the best, fix everything and expect the worst, but have satisfactory plans to mitigate it. This issue ended up being a simple fix that could be applied by changing a value in the live CTFd sql database.
<img src="/assets/2023-09-11/2.png"/>

Another issue that arose was downtime on our challenge server during the live event. All of our challenge's remotes where containerized on the same challenge server, which ended up going down due to the ML PyJail challenge, which had memory leaks and caused the server to run out of memory over time (the server went down day 2 of the event). Luckily, our president was awake when it happened (shit hit the fan at 4am) and was able to quickly diagnose the issue and remediate it by restarting the server. In total the downtime of our remotes lasted 15 minutes and since it was so early in the morning, it was hardly noticable. I say that but our ticket system was flooded with people who were angry and running solely on coffee. We could have prevented this issue from happening again, and it probably would have been really simple (putting a max memory cap on the docker), but we were lazy and (luckily) rightfully assumed there was not enough time left in the competition for it to consume this much memory again and agreed to just restart the individual challenge if we saw otherwise. For future reference, it might also be smart to actually give each challenge its own server, especially challenges with a lot of moving components.

## Postface
<a name="postface"></a>
Hopefully I shared some insight into what goes into hosting a CTF and challenges that may have not been considered to future organizers out there. Hosting a CTF is fun, rewarding and a great way to give back to the security community. It is also a very proud moment to see people solving challenges you worked hard and even finding creative solutions to solve it. I highly recommend any group of people considering hosting, to just do it and reap the rewards of your labor. Hopefully, our troubles will be lessons to you and you'll have a few less things to worry about on your list of problems. See you all next year for PatriotCTF 24.

