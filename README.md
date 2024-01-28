# The GQDB Project

This is the core crate of the GQDB project. This library provides the fundamental building blocks of the GQDB Network.
This crate provides functions to :

* Generate stations key pairs
* Create, sign and verify Station, QSO and Certificate objects.
* json serde support for serialize and deserialize Station, QSO and Certificate objects.

## What is GQDB?

GQDB is a simple, open protocol that enables the global and decentralized exchange of QSO confirmation data (also known as QSL Cards).

## GQDB at a High Level

There are two main components: Clients and Storage nodes. Each station runs a client, and any station has the capability to run storage nodes.

Every station is identified by a public key, and every QSO is signed. Each client validates these signatures.

Clients retrieve data from storage nodes of their choice and publish data to  storage nodes of therir choice. Storage nodes then forward station and QSO data to other storage nodes within the network.

Stations can onboard other stations to the network by signing their public key, thereby building a chain of trust.
