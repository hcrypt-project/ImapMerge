ImapMerge
=========

A prototype of a merging IMAP-proxy


Consider the following situation: You have two different IMAP accounts and want to merge these into a single user agent view. This sounds rather trivial unless you have conflicts.

So, what conflicts could there be (for I'm an IMAP rookie, this list might very likely change over time)?

1. Folder names
2. ...
n. starttls


v0: Ok, let's just try to forward the imap commands to one remote server... (I expect this to be fairly easy).
