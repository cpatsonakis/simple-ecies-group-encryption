# simple-ecies-group-encryption

The problem that we are concerned with here is related to that of encrypting a message, i.e., arbitrary data, so that only a set of *qualified users* can decrypt it. The sender of a message should be able to select, on a per-message basis, the qualified user, or intended recipient, set. This repository contains simplified implementations of such a group encryption primitive.

# Disclaimer & Dependencies
The code of this repository was developed with the intent of being integrated in the [OpenDSU](https://github.com/PrivateSky/OpenDSU) codebase, as part of the [PharmaLedger H2020](https://pharmaledger.eu/) project's efforts. The group encryption implementations provided here are based on the ECIES implementation of our [js-mutual-auth-ecies](https://github.com/cpatsonakis/js-mutual-auth-ecies) repository. The ECIES implementation from the latter repository was, essentially, taken as it were and, along with the necessary supplementary modules, is included in the `lib/` folder. For more information regarding the ECIES implementation, we refer the interested reader to our extensive documentation in the aforementioned repository. We stress that none of our implementations introduce external dependencies and that, in the background, they are developed based on NodeJS's `crypto` module, which is essentially a wrapper of the OpenSSL C-based library implementation.

# Preconditions & Assumptions

The purpose of this section is to document the preconditions and assumptions based on which the code provided here was developed. This will, hopefully, provide the interested reader with a basic level of understanding on the intended, practical use of this repository's implementations. Moreover, it will allow us to clarify, in more detail, the exact nature of the problem that we are trying to solve, as well as, other subtle details that, in our view, are relevant and informative.

Undoubtedly, the term *group*, especially from a cryptographic point of view, is inherently vague and warrants further clarification. In our context, we employ a simplistic approach and define a group as a non-empty set G={pk<sub>1</sub>, ..., pk<sub>n</sub>}, n>0, where, for any i &#x2208; [1,n], pk<sub>i</sub> denotes the public key of the group's i<sup>th</sup> member. For instance, the set G<sub>4</sub>={pk<sub>1</sub>, pk<sub>2</sub>, pk<sub>3</sub>, pk<sub>4</sub>} defines a group that is comprised by four distinct members, for which it provides a listing of their respective public keys.

Clearly, even in our simplistic scenario, it is evident that the description provided above is nothing but a, partial one can argue, representation of a group. Indeed, in order to formulate a comprehensive description of what constitutes a group, one needs to address several issues that are far more challenging than its representation. An intuitive and informal list of such issues can be summarized as follows:

1. How is a group established?
1. How is a group identified?
1. Who, or what mechanism, controls group membership?
1. How does one discover cryptographic material related to the group, e.g., cryptographic keys and other auxiliary parameters/values?
1. How can one use a group's cryptographic material to compute a ciphertext that can be decrypted by the group?

All of the aforementioned considerations are related to what is commonly referred to as the *group management* problem. While this is an extremely important topic, we stress that it is out of the scope of this work. More specifically, and since we are concerned with group encryption here, we assume that there exists an external mechanism that allows an entity to **securely resolve** the set G. Depending on the context, one has several options for secure resolution of cryptographic material, the most prominent of which, especially for asymmetric key pairs, is the SSL/TLS hierarchy. However, there are other alternatives available that build on more modern advancements and provide for increased fault-tolerance in terms of trust and overall security by leveraging distributed ledger technologies (DLTs), e.g., blockchains. 

The group representations that we consider here are based on public key cryptography, which imposes severe limitations on the set of group scheme constructions that can be coupled with the group encryption schemes provided here. However, even if we approached this issue from the opposite direction, i.e., if we first tackled the topic of group management, which also solidifies a group's cryptographic material, it is evident that similar limitations, and perhaps more stringent, would apply for the group encryption scheme. In short, there is no one size fits all and in the context of this exercise, we have decided to proceed with the modest assumption of public key cryptography.

Lastly, in the interest of clarity, we stress that we are not concerned here with the message delivery system that will be used to transmit the encrypted message to the group. For instance, the transport mechanism and even security properties related to, e.g., whether a message is delivered to all group members, or a subset of them, are considered out of scope of this exercise. Broadly speaking, we focus on providing authenticated encryption guarantees.

# Requirements



- **Ciphertext Size:** 



The size of the ciphertext **MUST** be some sub-linear function of the recipient set's cardinality. Ideally, the size of the ciphertext **SHOULD** be constant. This directly affects the incurred communication overhead. *Note: We are not concerned so much about the size of the ciphertext.*
- **User Storage:** The state maintained by users **SHOULD** be reasonably bounded. At this point, it is important to note that cryptographic protocols typically involve parameters and values that are a function of the:
  - Security parameter.
  - Maximum number of participants, or message recipients.
  
  We consider the aforementioned storage requirements as acceptable, as long as, they are related to **system-wide** parameters and values. We stress, however, that these should not pose any restrictions, nor be dependent in any way or form with the recipient set of the ciphertext. Put simply, the sender and the corresponding intended recipient set of a ciphertext **MUST** be able to reuse these parameters and values across an arbitrary amount of transmissions.
- **Computational Complexity:** Encryption and decryption **SHOULD** be efficient and, more importantly, suitable for practical, real-world deployment, e.g., in the order of a few hundreds of milliseconds for reasonably-sized messages and intended recipient sets. *Note: In the order of a few seconds for encryption and decryption is fine.*
- **Dynamic Membership:** The set of participants in the system **MUST** be amenable to change over time, i.e., mechanisms that provide for revocation and addition of new participants are a fundamental requirement. These mechanisms **SHOULD** involve minimal, or ideally zero, overhead to existing participants.
- **Sender Anonymity:** When communicating internally in a group, we do not want sender anonymity. When a group receives a message from an external party, we want sender anonymity.
- **Receiver Anonymity:** No.

# Overview

In the following, we provide a succinct overview of the ECIES implementations that are included in this repository:

#

