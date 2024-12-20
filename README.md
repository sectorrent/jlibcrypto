# jlibcrypto

A Quantum resistant crypto library for Java.

Why / About
-----
Although there are other libraries for Java that offer Quantum resistant algorithms there are not many. This project is a way for SecTorrent to not rely on other projects for security.
As we get closer to an era where Quantum Computing is closer to being capable of breaking encryption its better to start a project with algorithms that can handle that than to scramble trying
to implement it later on.

**Quantum Proof Algorithms**
| Algorithms | Support                                         |
| ---        | ---                                             |
| Sphincs+   | Done                                            |
| Kyber      | In Progress                                     |
| NTRU       | Not planned                                     |

**Non Quantum Proof Algorithms**
| Algorithms | Support                                         |
| ---        | ---                                             |
| SHA-256    | Done                                            |
| CRC32c     | Done                                            |

I have implemented non-quantum proof hashing algorithms as SHA-256 is required for Sphincs+ and CRC32c is required for Kademlia, however neither is a security risk of any sense.
