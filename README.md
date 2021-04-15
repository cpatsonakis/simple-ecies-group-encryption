# Simple, ECIES-Based, Group Encryption

The problem that we are concerned with here is related to that of encrypting a message, i.e., arbitrary data, so that only a set of *qualified users* can decrypt it. The sender of a message should be able to select, on a per-message basis, the qualified user, or intended recipient, set. This repository contains simplified implementations of such a group encryption primitive.

# Disclaimer & Dependencies
The code of this repository was developed with the intent of being integrated in the [OpenDSU](https://github.com/PrivateSky/OpenDSU) codebase, as part of the [PharmaLedger H2020](https://pharmaledger.eu/) project's efforts. The group encryption implementations provided here are based on the ECIES implementation of our [js-mutual-auth-ecies](https://github.com/cpatsonakis/js-mutual-auth-ecies) repository. The ECIES implementation from the latter repository was, essentially, taken as it were and, along with the necessary supplementary modules, is included in the `lib/` folder. For more information regarding the ECIES implementation, we refer the interested reader to our extensive documentation in the aforementioned repository. We stress that none of our implementations introduce external dependencies and that, in the background, they are developed based on NodeJS's `crypto` module, which is essentially a wrapper of the OpenSSL C-based library implementation.

# Preconditions & Assumptions

The purpose of this section is to document the preconditions and assumptions that formed the basis of our reasoning for designing and implementing the group encryption schemes provided here. This will, hopefully, provide the interested reader with preliminary insight regarding the intended and practical use of this repository's implementations. Moreover, it will allow us to gradually clarify, in more detail, the exact nature of the problem that we are trying to solve, as well as, other subtle details that, in our view, are relevant and informative.

Undoubtedly, the term *group*, especially from a cryptographic point of view, is inherently vague and warrants further clarification. In our context, we employ a simplistic approach and define a group as a non-empty set G={pk<sub>1</sub>, ..., pk<sub>n</sub>}, n>0, where, for any i &#x2208; [1,n], pk<sub>i</sub> denotes the public key of the group's i<sup>th</sup> member. For instance, the set G<sub>4</sub>={pk<sub>1</sub>, pk<sub>2</sub>, pk<sub>3</sub>, pk<sub>4</sub>} defines a group that is comprised by four distinct members, for which it provides a listing of their respective public keys.

Clearly, even in our simplistic scenario, it is evident that the description provided above is nothing but a, partial one can argue, representation of a group. Indeed, in order to formulate a comprehensive description of what constitutes a group, one needs to address several issues that are far more challenging than its representation. An intuitive and informal list of such issues can be summarized as follows:

1. How is a group established?
1. How is a group identified?
1. Who, or what mechanism, controls group membership?
1. How does one discover cryptographic material related to the group, e.g., cryptographic keys and other auxiliary parameters/values?
1. How can one use a group's cryptographic material to compute a ciphertext that can be decrypted by the group?

All of the aforementioned considerations are related to what is commonly referred to as the *group management* problem. While this is an extremely important topic, we stress that it is out of the scope of this work. More specifically, and since we are concerned with group encryption here, we assume that there exists an external mechanism that allows an entity to **securely resolve** the set G. Depending on the context, one has several options for secure resolution of cryptographic material, the most prominent of which, especially for asymmetric key pairs, is the SSL/TLS hierarchy. However, there are other alternatives available that build on more modern advancements and provide for increased fault-tolerance in terms of trust, as well as, overall security by leveraging distributed ledger technologies (DLTs), e.g., blockchains. 

The group representations that we consider here are based on public key cryptography, which imposes severe limitations on the set of group scheme constructions that can be coupled with the group encryption schemes provided here. However, even if we approached this issue from the opposite direction, i.e., if we first tackled the topic of group management, which by definition solidifies a group's cryptographic material, it is evident that similar limitations, and perhaps more stringent, would apply for the group encryption scheme. In short, there is no one size fits all and in the context of this exercise, we have decided to proceed with the modest assumption of employing public key cryptography as a basis.

In the interest of clarity, we stress that we are not concerned here with the message delivery system that will be used to transmit the encrypted message to the group. For instance, the transport mechanism and even security properties related to, e.g., whether a message is delivered to all group members, or a subset of them, are considered out of scope of this exercise. Broadly speaking, we focus on providing authenticated encryption guarantees.

Conceptually, when one is tasked to provide a technical solution to a problem, or design a solution for one or more use cases, it is rarely the case that there are no additional constraints or limitations. For instance, based on the discussion up to this point, one could argue that employing public key cryptography as a basis is a constraint. From a theoretical cryptography point of view, and more specifically, when dealing with public key cryptosystems over elliptic curves, which is the case in our context, one could argue that we still have mathematical tools at our disposal, such as operations on the underlying elliptic curve group, that would allow us to engage in the dark art of crypto magic. However, we stress that this is not the case here. Indeed, from a technical standpoint, we have a limited set of tools at our disposal that can only be used in a black-box fashion, an explicit list of which is as follows: 1) hash functions, i.e., mainly SHA-2-256, 2) symmetric ciphers, typically some instantiation of AES (not ECB!), 3) HMACs, 4) digital signatures, more specifically, ECDSA and, 5) ECDH(E), i.e., either ephemeral or not. A knowledgeable reader will notice that these tools, especially when employed in a black-box fashion, are inadequate to provide efficient solutions for multi-party protocols.

# Requirements

We now shift our attention on the group encryption scheme itself and provide a high-level description of technical requirements that the implementations should abide by. 

Arguably, the most natural starting point since we are dealing with encryption is the ciphertext itself. More specifically, in the context of group encryption, the size of the ciphertext is an important factor. Indeed, it would be beneficial if its size were some sub-linear function of the group's cardinality, or, ideally, constant. However, for the application settings that concern us, the size of the ciphertext is not that important, i.e., it is considered acceptable even if the size of the ciphertext is a linear function of the group's cardinality. Clearly, a linearly sized ciphertext imposes a linear communication complexity, which is a fact that we are conscious of and deem as acceptable in our context.

The state maintained by users, i.e., group members, should be reasonably bounded, which is a point that warrants a small level of clarification. Typically, multi-party cryptographic protocols involve parameters that, in many cases, are linear to the maximum number of participants. Put simply, when a multi-party protocol is setup, it generally is the case that an upper bound on the participant set is specified. However, these parameters, typically, are reusable across an arbitrary number of protocol invocations. In our context, these aforementioned storage requirements are acceptable.

The computational complexity, or efficiency, of encryption and decryption is another aspect that, as hinted by the discussion regarding ciphertext size, is not a matter of grave concern for us. Loosely speaking, for reasonably-sized messages and group cardinalities, we consider an execution time that lies in the order of a few seconds as acceptable for these algorithms.

When discussing the topic of secure communication in two party settings, it is standard practice to employ an authentication encryption scheme, i.e., to guarantee confidentiality and integrity of message transmission. We require that our construction(s) provide the same properties, albeit in a multi-party setting.

Anonymity is, undoubtedly, an important aspect of secure communication. For instance, and assuming a two party setting for ease of description, there are schemes in which the sender is completely anonymous, both to a potential man-in-the-middle (MITM), as well as, the intended message recipient. ECIES, which we employ as a building block, is an encryption scheme that provides for sender anonymity. For our use cases, depending on the application context, there are cases where sender anonymity is required and others where it is not, i.e., we need to be able to support both. On a similar note, one might require to, instead, preserve the anonymity of the intended recipient in some cases. We stress that for our use cases receiver anonymity is discouraged.

Lastly, the construction(s) must provide for both forward and backward secrecy.

# Overview




In the following, we provide a succinct overview of the ECIES implementations that are included in this repository:

# ECIES-

# Note on Group Encryption

The knowledgeable reader


# Security Drawbacks

In the interest of transparency, in the following we provide a list of security-related drawbacks of the
