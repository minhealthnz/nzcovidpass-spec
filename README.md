# NZ COVID Pass Documentation

This repository contains documentation for the NZ COVID Pass specification, which includes the My Vaccine Pass. 

The latest detailed technical specification is published at [nzcp.covid19.health.nz](https://nzcp.covid19.health.nz). 

> ⚠️ **Please note:** The information contained in this repository, and in the specification, is being released early to give
> businesses and other interested parties time to understand how the technology supporting vaccination certificates within the
> COVID-19 Protection Framework will work.
> 
> Policy and legislation that govern domestic use of health proofs is still being drafted and subject to consideration, therefore 
> the detail outlined here is subject to change.
> 
> This repository will also be updated with additional technical information and implementation guidance as it becomes available. 
> If you have questions about the technical specification, you can email integration@health.govt.nz. Information about obligations 
> as a business, or how the COVID-19 Protection Framework will work for you, can be found 
> at [covid19.govt.nz](https://covid19.govt.nz/alert-levels-and-updates/covid-19-protection/).
>
> Watch this repository to be notified of updates as they are published.
> 

## Passes

This specification has been developed by the Ministry of Health as part of the response to COVID-19. 

It is principally designed to provide a technical standard for creating verifiable proofs of a health status for New Zealand use, including proof of vaccination for COVID-19.

The spec currently defines the following types of pass:

Pass Name                               | Purpose
----------------------------------------|--------------------------------------
[My Vaccine Pass](#my-vaccine-pass)     | A verifiable proof that the *person named* on the pass is *considered vaccinated* for COVID-19, *until the pass expires*.

### My Vaccine Pass

The Pass provides a verifiable proof that the person named on the pass is considered vaccinated for COVID-19, until the pass expires.

A person is eligible for a My Vaccine Pass when they meet certain health requirements for COVID-19 vaccination. These requirements are evaluated at the time the person requests the pass. If the person meets the requirements, the pass will be issued and valid for a set period of time. 

At any time, or once a pass expires, a person can request a new pass. Eligibility criteria will be re-evaluated and, if they are met, another pass will be issued.

Requirements for eligibility of a pass may change over time. Passes already issued will remain valid until they expire. In extreme scenarios all passes may be revoked if required.

## Terminology

![Terminology for NZ COVID Pass](https://user-images.githubusercontent.com/344000/140439118-7eb77eb3-c46e-41e3-ad89-8c72aa117812.png)

Term          | Defintion
--------------|--------------------------------------
Issuer        | The entity issuing the Pass. At present this is only the Ministry of Health
Pass          | A paper or digital copy of a proof of vaccination. Contains a QR code with a digital signature that proves the pass hasn’t been tampered with
Consumer      | An individual in NZ who needs to prove vaccination status
Verifier      | A business or other entity that needs to check if an individual is vaccinated
Verifier App  | Technology used by a Verifier to scan the QR code on a Pass and display a result

## Trust framework and digital signatures

The NZ COVID Pass uses [DID:WEB](https://w3c-ccg.github.io/did-method-web/) identifiers to resolve the public key used to verify the digital signature. At this time the Ministry of Health is the only authority issuing passes.

The specification contains the current [trusted issuers](https://nzcp.covid19.health.nz/#trusted-issuers). 

## Verifier Apps

The Ministry of Health is building a free Verifier App to be made available on the App Store and Google Play. Anyone can download this and use it to scan and verify a pass, and no login or identity is required to be able to use the app. The source code for this app will also be published on GitHub, along with additional documentation for how it works.

### Third party verifier apps
It is also possible for others to build their own verifier apps, to incorporate verification into their existing technology and business processes. The [specification](https://nzcp.covid19.health.nz) is intended to provide the necessary detail for implementing your own verifier app, including worked examples.

There are some considerations you should make when building your own verification apps:
* Scanning the content of the QR code is the only way to confirm the pass has been issued by the Ministry of Health, and has not been tampered with. The details printed visually on the pass should not be trusted.
* Your verifier app can work offline after resolving the DID:WEB identifier and downloading a copy of the [current public keys](https://nzcp.identity.health.nz/.well-known/did.json). You should also periodically check this in case new public keys are published. If you are presented a pass and you don't have the latest copy of the DID document, you will not be able to verify the pass is authentic.
* You should avoid storing any details from the pass, unless there is a reason to do so. We recommend adopting a privacy-first stance and consider whether you have a legitimate purpose to hold this data.

> ⚠️ **Note:** Legislation is being drafted to limit the collection and use of data from an NZ COVID Pass.

### Verification steps

The specification contains a full summary of the steps required to [verify an NZ COVID Pass](https://nzcp.covid19.health.nz#steps-to-verify-an-new-zealand-covid-pass). At a high level you should:
* Decode the contents of the QR code, per the CWT standards (formal documentation TBC)
* Check the `iss` field is an authorised issuer, based on the [trusted issuers](https://nzcp.covid19.health.nz/#trusted-issuers) list.
* Check the CWT header for the key id (`kid`) used to sign the pass. If not already cached, download the latest list of public keys by resolving the DID:WEB identifer in the `iss` field.
* Confirm the digital signature is valid, using the resolved public key and CWT process
* Confirm the `exp` date is in the future
* Confirm the `nbf` date is in the past
* Confirm the `version` number is above the minimum published and [accepted version](https://nzcp.covid19.health.nz/#cwt-headers)
* Display the name/dob details for the human verifier to check, or check these against an existing identity record

## QR Code structure

The QR code is assembled using existing open specifications.
* Underlying data model based on W3C Verifiable Credentials
* Each pass has an expiry date (exp) and not before date (nbf)
* Issuer uses DID:WEB identifiers to resolve the public key used to verify the pass digital signature.
* CBOR Web Token ([CWT](https://datatracker.ietf.org/doc/html/rfc8392)) is the cryptographic structure used to represent claims in the pass, which uses Concise Binary Object Representation ([CBOR](https://datatracker.ietf.org/doc/html/rfc7049)) and CBOR Object Signing and Encryption ([COSE](https://datatracker.ietf.org/doc/html/rfc8152)). CWT is derived from JSON Web Token (JWTs), but is more compact.
* ECDSA with P-256 for the digital signature algorithm
* Base32 encoding of CWT into QR code in Alphanumeric mode, using a prefix of NZCP:/ and a version number. [Some manipulation](https://nzcp.covid19.health.nz/#adding-base32-padding) of the Base32 may be required when decoding.

The specification has full examples of the QR code and a worked example for how to decode it in the [examples section](https://nzcp.covid19.health.nz/#examples).


