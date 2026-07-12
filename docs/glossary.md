# Glossary

This glossary uses plain descriptions first. Formal definitions and exceptions
are introduced in the chapter where they affect code.

| Term | Plain meaning |
|---|---|
| authoritative server | server answering from DNS data it owns |
| byte / octet | eight bits; one basic packet unit |
| cache | temporarily stored answer with an expiry time |
| class | DNS namespace; this book mainly uses Internet (`IN`) |
| CNAME | record saying one name is an alias of another name |
| compression pointer | two bytes referring to a name suffix elsewhere in the packet |
| delegation | transfer of responsibility for a subtree to other name servers |
| domain name | ordered labels ending at the root, such as `www.example.com.` |
| EDNS | extension mechanism that adds capabilities without replacing DNS headers |
| flag | yes/no value occupying one bit |
| glue | address records supplied with a delegation so its servers can be reached |
| label | one component of a name, such as `example` or `com` |
| name server | process that accepts DNS questions and sends DNS responses |
| NODATA | name exists, but the requested record type does not |
| NXDOMAIN | queried name does not exist |
| question | queried name, record type, and class |
| recursive resolver | service that finds a final answer on behalf of a client |
| referral | response directing a resolver to servers closer to the answer |
| resource record | owner name, type, class, TTL, and typed data |
| RFC | published Internet specification; normative RFC text defines required behavior |
| root | top of the DNS hierarchy, written as `.` |
| RRset | records sharing owner name, type, and class |
| stub resolver | small client that asks a recursive resolver to do the search |
| TCP | reliable byte-stream transport; DNS messages carry a length prefix on it |
| TTL | seconds for which a record may remain cached |
| UDP | datagram transport normally tried first for DNS queries |
| wildcard | owner beginning with `*` that may synthesize answers for missing names |
| wire format | exact bytes exchanged over the network |
| zone | administratively managed slice of the DNS name tree |
