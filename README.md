# `query-farm-flight-server`

A robust Python framework for building [Apache Arrow Flight](https://arrow.apache.org/blog/2020/05/06/introducing-arrow-flight/) servers that integrate seamlessly with the [Airport extension](https://airport.query.farm) for [DuckDB](https://duckdb.org/).

This framework enables secure, efficient, and scalable server implementations with features such as authentication, schema management, and predicate pushdown for data queries.

---

## 🚀 Key Features

* ✅ **Authentication & Authorization**: Pluggable backends for secure access control
* 📚 **Schema & Table Management**: Full support for schema evolution and DDL operations
* 📈 **Rate Limiting & Usage Tracking**: Monitor and control client usage
* 🧩 **Extensible & Type-Safe**: Built for safe and scalable extension
* ☁️ **AWS Integration**: Support for S3 storage and DynamoDB-based authentication

---

## 🛰 Arrow Flight Server Support

Designed to simplify the development of Arrow Flight servers:

* Generic, reusable base classes for implementing Arrow Flight endpoints
* Standardized handlers for all major data operations
* Supports both streaming and batch workflows
* Typed parameter parsing and serialization for safer code

---

## 🔐 Authentication System

Unified interface for multiple authentication backends:

* In-memory backend for local development and tests
* DynamoDB backend for scalable, persistent auth
* Naive implementation for prototyping
* Token-based auth with built-in rate limiting

---

## 🔄 Data Serialization

Efficient and type-safe serialization for Airport-compatible servers:

* Parameter serialization using [MessagePack](https://msgpack.org/)
* Record batch transfer using Arrow IPC
* Support for DuckDB expression (de)serialization
* Optimized binary payloads for Arrow Flight actions

---

## 🛠 Admin CLI

Built-in command-line tool for managing and monitoring your server:

* Create and manage user accounts and tokens
* Monitor usage and generate reports
* Manage configuration settings

---

## 🧩 Designed for Extension

Whether you're integrating new storage backends, customizing authentication, or implementing complex business logic, `query-farm-flight-server` is built to scale with your needs while keeping your codebase clean and type-safe.


# Getting Started

Installation

```python
pip install query-farm-flight-server
```

# Development

This python module is designed to be extended for specific database backends. Implement the abstract methods in `BasicFlightServer` to create a custom server for your specific data source.

The project maintains strict type safety through Python's typing system and Pydantic models, ensuring robust API contracts.

## Author

This Python module was created by [Query.Farm](https://query.farm).

# License

MIT Licensed.
