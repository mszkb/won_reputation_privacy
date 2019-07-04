# Web of Needs - Privacy Preserving Reputation System

Implementation of the idea of [PrivateRide](https://petsymposium.org/2017/papers/issue2/paper09-2017-2-source.pdf) in Java 8.

[Web of Needs: Finding and cooperating with people. Protocol, not platform. Decentralized. Linked Data. Open Source.](https://github.com/researchstudio-sat/webofneeds)

## Setup

- Clone the Repo and import it into IntelliJ and import Maven Dependencies.
- Make sure you "mvn install" [WoN-Core of my fork](https://github.com/mszkb/webofneeds) 
- Reimport Maven dependencies

TODO: use Maven to build and test the Repo without IntelliJ

## Tests

This work contains test-cases implemented with JUnit. These test classes provide an overview of how the implementation was implemented and how to use the individual classes.
We provide tests with and without sockets.

Socket implementation are the prototype for the Won network. 
The tests without sockets can be used as a library.

The test class of the CLI tool is inside src/test/java/ structure.
To test the CLI tool manually you can open up 3 terminal windows (alice, bob, SP).

## Documentation

We simulate the Reputation-Token acquiring process with plain Java Sockets. This is a simple implementation of the Idea presented in PrivateRide and the prototype for the WoN.

In WoN we use so-called bots which can perform tasks on behalf of the user. eg. acquiring ACL-Tokens or Reputation-Tokens. These tokens are based on complex computation which should be hidden from the user. The only thing the user is interested being able to create an Atom or rate another User.

### Theory: Reputation-Token

To see how the reputation token algorithm works between user, you can look at /src/test/java/WonProtocolE2ETest.java. In this test file we simulate the exchange of the reputation-tokens.
Quick overview between the Users Bob and Alice:

- Bob and Alice registers to the system to get a certificate (registerWithSystem)
- They generate a random number and hash them (createRandomHash)
- They exchange the random hashed number (exchangeHash)
- They sign the random hashed number from the other person with their private key (signHash)
- They create a ReputationToken which contains their certificate and the signed hashed number from the other person (createReputationToken)
- They send this RepuationToken to the SP to get a blind Signature of the bytes of that token (blindAndSign)
- They exchange the blind signed ReputationToken (exchangeReputationToken)
- They send the ReputationToken along with the original Hash to the SP to verify it (verify)

### Sockets

To simulate these Algorithms we created a prototype with plain Java Sockets /src/test/java/WonBotTest.java.
The Test-Method is considerd be a Bot of a specific side. This is side is defined in the name.
eg. runAlice means, we test Alice and test and method is Bob.
runBob means, we test Bob and the method is Alice.
runSP means, we test SP and the method is Bob or Alice. (it does not matter because Bob and Alice send the same data)

#### Blind Signature

To test blind signature over the network look at the Test-Method runSP_testBlindAndSign_valid() in WonBotTest.java
We take the side of Alice (or Bob) and create a random hashed number. We send the random hashed number to the SP. The SP blinds it and signs with her private key and returns to Alice.
In the next step we want to verify that blind signature. In the real Won we exchange the blind signature first and verify it afterwards.

#### Reputation Token

To test the exchange of Reputation Tokens look at runBob_testProtocol() in WonBotTest.java

## TODO Github-wise

- provide installation guide
- how to test
- how to use classes and functionality


