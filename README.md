# **Resilient Anonymous Communication for Everyone (RACE) Raven Guide**

## **Table of Contents**
- [**Introduction**](#--introduction--)
  * [**Design Goals**](#--design-goals--)
  * [**Security Considerations**](#--security-considerations--)
- [**Scope**](#--scope--)
  * [**Audience**](#--audience--)
  * [**Environment**](#--environment--)
  * [**License**](#--license--)
  * [**Additional Reading**](#--additional-reading--)
- [**Implementation Overview**](#--implementation-overview--)
- [**Implementation Organization**](#--implementation-organization--)
  * [source](#source)
  * [kit](#kit)
- [**How To Build**](#--how-to-build--)
- [**How To Run**](#--how-to-run--)

<br></br>

## **Introduction**
This plugin transmits data by encoding data into PGP-encrypted email bodies and emailing to recipients with realistic sending times and sizes.
</br>

### **Design Goals**
Provide indirect communications between RACE clients and servers that prevents adversarial identification of abnormal behavior based on emailing patterns. The primary contributions of this plugin are the sophisticated models of user email behavior based on applying a GAN training process to produce generative models of user behavior.

### **Security Considerations**
This plugin is a research prototype and has not been the subject of an independent security audit or extensive external testing.

This channel "encodes" encrypted data into what appear to be PGP encrypted email bodies. Therefore running Raven in an environment with adversaries willing to block such emails, or with small enough numbers of legitimate PGP users to suspect anyone using PGP as a Raven user, is unlikely to work long-term.


<br></br>

## **Scope**
This developer guide covers the  development model, building artifacts, running, and troubleshooting.  It is structured this way to first provide context, associate attributes/features with source files, then guide a developer through the build process.  

</br>

### **Audience**
Technical/developer audience.

### **Environment**

### **License**
Licensed under the APACHE 2.0 license, see LICENSE file for more information.

### **Additional Reading**
* [RACE Quickstart Guide](https://github.com/tst-race/race-quickstart/blob/main/README.md)

* [What is RACE: The Longer Story](https://github.com/tst-race/race-docs/blob/main/what-is-race.md)

* [Developer Documentation](https://github.com/tst-race/race-docs/blob/main/RACE%20developer%20guide.md)

* [RIB Documentation](https://github.com/tst-race/race-in-the-box/tree/2.6.0/documentation)

<br></br>

## **Implementation Overview**
The implementation works with containerized email servers for local RIB deployments, as well as Gmail accounts.

<br></br>

## **Implementation Organization**
### source
Contains source code for the Raven plugin, including interacting with email servers and RACE APIs and the Raven user model.

### kit
Contains configuration generation code and, after building, runtime code for each supported architecture and node type.

<br></br>

## **How To Build**
Build is done inside a race-sdk docker container, run:
```
./build_artifacts_in_docker_image.sh
```
This will produce a `kit` directory that can be used in a RACE deployment. Note that it will only produce artifacts for the host architecture.

</br>

## **How To Run**

Include in a RACE deployment for server-to-server communications by adding the following arguments to a `rib deployment create` command:
```
--comms-channel=raven --comms-kit=<kit source for raven>
```

</br>
