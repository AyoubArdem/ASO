"""Authorization-aware memory access interfaces and local persistence."""

from __future__ import annotations

import json
import hashlib
import importlib
import os
import sqlite3
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .config import (
    AgentRequest,
    AuditEvent,
    Decision,
    GuardDecision,
    MemoryRequest,
    Operation,
    ProviderCredentials,
    SecurityContext,
    StoreConfig,
)
from .memory_guard import CyberAI, MemoryGuard

DECISIONS = {"accept", "deny", "quarantine"}
VECTOR_PROVIDERS = {"qdrant", "pinecone", "weaviate", "milvus", "chroma", "faiss", "pgvector", "vespa"}


def _managed_provider_config(provider: str, config: dict[str, Any]) -> dict[str, Any]:
    """Resolve application credentials without placing secrets in adapter metadata."""
    credentials = config.pop("credentials", None)
    if credentials is None:
        return config
    if not isinstance(credentials, ProviderCredentials):
        raise TypeError("credentials must be an application-owned ProviderCredentials")
    if credentials.provider != provider:
        raise ValueError("credential provider does not match adapter provider")
    resolved = credentials.resolve()
    if resolved.get("endpoint"):
        config.setdefault("url", resolved["endpoint"])
    if resolved.get("api_key"):
        config.setdefault("api_key", resolved["api_key"])
    if resolved.get("access_key"):
        config.setdefault("access_key", resolved["access_key"])
    if resolved.get("secret_key"):
        config.setdefault("secret_key", resolved["secret_key"])
    if resolved.get("region"):
        config.setdefault("region", resolved["region"])
    config["timeout"] = resolved["timeout_seconds"]
    return config


class SDKUnavailable(RuntimeError):
    """Raised when an application-configured provider SDK is unavailable."""


class ApplicationManagedBackend(ABC):
    """Backend contract; credentials and clients stay inside the application."""

    @abstractmethod
    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any: ...


class SQLiteBackend(ApplicationManagedBackend):
    """Provider backend for an application-owned SQLite memory database.

    This connection is deliberately separate from ``DatabaseManager``. The
    latter is reserved for Memory Guard metadata and audit records.
    """

    def __init__(self, database_path: str | Path = "agent_memory.db") -> None:
        self.database_path = str(database_path)
        self._connection: sqlite3.Connection | None = None

    def _connection_for(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self.database_path)
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_items (
                    memory_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._connection.commit()
        return self._connection

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        connection = self._connection_for()
        if operation in {"write", "update"}:
            connection.execute(
                "INSERT OR REPLACE INTO memory_items VALUES (?, ?, ?, ?)",
                (memory_id, request.agent_id, request.data, datetime.now(timezone.utc).isoformat()),
            )
            connection.commit()
            return None
        if operation in {"read", "search"}:
            row = connection.execute(
                "SELECT encrypted_payload FROM memory_items WHERE memory_id = ? AND agent_id = ?",
                (memory_id, request.agent_id),
            ).fetchone()
            return row[0] if row else None
        if operation == "delete":
            cursor = connection.execute(
                "DELETE FROM memory_items WHERE memory_id = ? AND agent_id = ?",
                (memory_id, request.agent_id),
            )
            connection.commit()
            return cursor.rowcount > 0
        raise ValueError(f"unsupported SQLite operation: {operation}")

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None


def _json_payload(request: AgentRequest) -> str:
    return json.dumps(request.data, ensure_ascii=False, separators=(",", ":"))


class QdrantBackend(ApplicationManagedBackend):
    def __init__(self, collection: str = "memory", url: str | None = None, api_key: str | None = None) -> None:
        self.collection = collection
        self.url = url or os.environ.get("QDRANT_URL")
        self.api_key = api_key or os.environ.get("QDRANT_API_KEY")
        try:
            client_class = importlib.import_module("qdrant_client").QdrantClient
        except ImportError as error:
            raise SDKUnavailable("install qdrant-client for QdrantBackend") from error
        if not self.url:
            raise SDKUnavailable("QDRANT_URL is required")
        self._client = client_class(url=self.url, api_key=self.api_key)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        client = self._client
        if operation in {"write", "update"}:
            vector = AgentDB._embedding(request.data)
            payload = {"ciphertext": request.data, "agent_id": request.agent_id}
            point = importlib.import_module("qdrant_client.http.models").PointStruct(
                id=memory_id, vector=vector, payload=payload
            )
            client.upsert(collection_name=self.collection, points=[point], wait=True)
            return None
        if operation in {"read", "search"}:
            result = client.retrieve(collection_name=self.collection, ids=[memory_id], with_payload=True)
            return result[0].payload.get("ciphertext") if result else None
        if operation == "delete":
            client.delete(collection_name=self.collection, points_selector=[memory_id], wait=True)
            return True
        raise ValueError(f"unsupported Qdrant operation: {operation}")


class PineconeBackend(ApplicationManagedBackend):
    def __init__(self, index: str = "memory", namespace: str = "default", api_key: str | None = None) -> None:
        self.index_name = index
        self.namespace = namespace
        self.api_key = api_key or os.environ.get("PINECONE_API_KEY")
        try:
            pinecone = importlib.import_module("pinecone")
        except ImportError as error:
            raise SDKUnavailable("install pinecone for PineconeBackend") from error
        if not self.api_key:
            raise SDKUnavailable("PINECONE_API_KEY is required")
        self._index = pinecone.Pinecone(api_key=self.api_key).Index(self.index_name)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        index = self._index
        if operation in {"write", "update"}:
            index.upsert([(memory_id, AgentDB._embedding(request.data), {"ciphertext": request.data})], namespace=self.namespace)
            return None
        if operation in {"read", "search"}:
            result = index.fetch([memory_id], namespace=self.namespace)
            vector = result.vectors.get(memory_id)
            return vector.metadata.get("ciphertext") if vector else None
        if operation == "delete":
            index.delete(ids=[memory_id], namespace=self.namespace)
            return True
        raise ValueError(f"unsupported Pinecone operation: {operation}")


class S3Backend(ApplicationManagedBackend):
    def __init__(self, bucket: str, prefix: str = "memory", region: str | None = None) -> None:
        self.bucket, self.prefix, self.region = bucket, prefix.strip("/"), region
        try:
            boto3 = importlib.import_module("boto3")
        except ImportError as error:
            raise SDKUnavailable("install boto3 for S3Backend") from error
        self._client = boto3.client("s3", region_name=self.region)

    def _key(self, memory_id: str) -> str:
        return f"{self.prefix}/{memory_id}.json"

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        client, key = self._client, self._key(memory_id)
        if operation in {"write", "update"}:
            client.put_object(Bucket=self.bucket, Key=key, Body=_json_payload(request).encode(), ContentType="application/json", ServerSideEncryption="AES256")
            return None
        if operation in {"read", "search"}:
            try:
                return json.loads(client.get_object(Bucket=self.bucket, Key=key)["Body"].read().decode())
            except client.exceptions.NoSuchKey:
                return None
        if operation == "delete":
            client.delete_object(Bucket=self.bucket, Key=key)
            return True
        raise ValueError(f"unsupported S3 operation: {operation}")


class RedisBackend(ApplicationManagedBackend):
    def __init__(self, namespace: str = "memory", url: str | None = None) -> None:
        self.namespace = namespace.strip(":")
        self.url = url or os.environ.get("REDIS_URL")
        try:
            redis = importlib.import_module("redis")
        except ImportError as error:
            raise SDKUnavailable("install redis for RedisBackend") from error
        if not self.url:
            raise SDKUnavailable("REDIS_URL is required")
        self._client = redis.Redis.from_url(self.url, decode_responses=True)
        self._client.ping()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        client, key = self._client, f"{self.namespace}:{memory_id}"
        if operation in {"write", "update"}:
            client.set(key, _json_payload(request))
            return None
        if operation in {"read", "search"}:
            value = client.get(key)
            return json.loads(value) if value else None
        if operation == "delete":
            return bool(client.delete(key))
        raise ValueError(f"unsupported Redis operation: {operation}")


class MongoBackend(ApplicationManagedBackend):
    def __init__(self, database: str = "memory", collection: str = "items", uri: str | None = None) -> None:
        self.database, self.collection_name = database, collection
        self.uri = uri or os.environ.get("MONGODB_URI")
        try:
            MongoClient = importlib.import_module("pymongo").MongoClient
        except ImportError as error:
            raise SDKUnavailable("install pymongo for MongoBackend") from error
        if not self.uri:
            raise SDKUnavailable("MONGODB_URI is required")
        self._client = MongoClient(self.uri, serverSelectionTimeoutMS=10000)
        self._client.admin.command("ping")
        self._collection = self._client[self.database][self.collection_name]

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        collection = self._collection
        if operation in {"write", "update"}:
            collection.replace_one({"_id": memory_id}, {"_id": memory_id, "payload": request.data}, upsert=True)
            return None
        if operation in {"read", "search"}:
            item = collection.find_one({"_id": memory_id})
            return item.get("payload") if item else None
        if operation == "delete":
            return collection.delete_one({"_id": memory_id}).deleted_count > 0
        raise ValueError(f"unsupported MongoDB operation: {operation}")


class DynamoDBBackend(ApplicationManagedBackend):
    def __init__(self, table: str, region: str | None = None) -> None:
        self.table_name, self.region = table, region
        try:
            boto3 = importlib.import_module("boto3")
        except ImportError as error:
            raise SDKUnavailable("install boto3 for DynamoDBBackend") from error
        self._table = boto3.resource("dynamodb", region_name=self.region).Table(self.table_name)
        self._table.load()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        table = self._table
        if operation in {"write", "update"}:
            table.put_item(Item={"memory_id": memory_id, "payload": request.data})
            return None
        if operation in {"read", "search"}:
            return table.get_item(Key={"memory_id": memory_id}).get("Item", {}).get("payload")
        if operation == "delete":
            table.delete_item(Key={"memory_id": memory_id})
            return True
        raise ValueError(f"unsupported DynamoDB operation: {operation}")


class ElasticsearchBackend(ApplicationManagedBackend):
    def __init__(self, index: str = "memory", url: str | None = None, api_key: str | None = None) -> None:
        self.index, self.url = index, url or os.environ.get("ELASTICSEARCH_URL")
        self.api_key = api_key or os.environ.get("ELASTICSEARCH_API_KEY")
        try:
            Elasticsearch = importlib.import_module("elasticsearch").Elasticsearch
        except ImportError as error:
            raise SDKUnavailable("install elasticsearch for ElasticsearchBackend") from error
        if not self.url:
            raise SDKUnavailable("ELASTICSEARCH_URL is required")
        self._client = Elasticsearch(self.url, api_key=self.api_key, request_timeout=10)
        if not self._client.ping():
            raise SDKUnavailable("Elasticsearch endpoint is unavailable")

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        client = self._client
        if operation in {"write", "update"}:
            client.index(index=self.index, id=memory_id, document={"payload": request.data}, refresh=True)
            return None
        if operation in {"read", "search"}:
            try:
                return client.get(index=self.index, id=memory_id)["_source"].get("payload")
            except Exception:
                return None
        if operation == "delete":
            client.delete(index=self.index, id=memory_id, refresh=True, ignore=[404])
            return True
        raise ValueError(f"unsupported Elasticsearch operation: {operation}")


def _required_module(module_name: str, install_name: str | None = None) -> Any:
    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        raise SDKUnavailable(f"install {install_name or module_name} before starting this provider") from error


class WeaviateBackend(ApplicationManagedBackend):
    def __init__(self, collection: str, url: str, api_key: str | None = None) -> None:
        module = _required_module("weaviate", "weaviate-client")
        auth = module.auth.AuthApiKey(api_key) if api_key else None
        self.client = module.connect_to_custom(url, auth_credentials=auth)
        self.collection = self.client.collections.get(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            self.collection.data.insert(properties={"ciphertext": request.data, "agent_id": request.agent_id}, uuid=memory_id)
            return None
        if operation in {"read", "search"}:
            item = self.collection.query.fetch_objects(filters=None, limit=1)
            return item.objects[0].properties.get("ciphertext") if item.objects else None
        if operation == "delete":
            self.collection.data.delete_by_id(memory_id)
            return True
        raise ValueError(f"unsupported Weaviate operation: {operation}")


class MilvusBackend(ApplicationManagedBackend):
    def __init__(self, collection: str, uri: str, token: str | None = None) -> None:
        module = _required_module("pymilvus")
        module.connections.connect(alias="default", uri=uri, token=token)
        self.module, self.collection_name = module, collection
        self.collection = module.Collection(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            vector = AgentDB._embedding(request.data)
            self.collection.insert([[memory_id, vector, request.data]])
            self.collection.flush()
            return None
        if operation in {"read", "search"}:
            rows = self.collection.query(expr=f'id == "{memory_id}"', output_fields=["payload"])
            return rows[0].get("payload") if rows else None
        if operation == "delete":
            self.collection.delete(f'id == "{memory_id}"')
            return True
        raise ValueError(f"unsupported Milvus operation: {operation}")


class ChromaBackend(ApplicationManagedBackend):
    def __init__(self, collection: str, host: str, port: int = 8000) -> None:
        module = _required_module("chromadb")
        self.collection = module.HttpClient(host=host, port=port).get_or_create_collection(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            self.collection.upsert(ids=[memory_id], documents=[_json_payload(request)], metadatas=[{"agent_id": request.agent_id}])
            return None
        if operation in {"read", "search"}:
            result = self.collection.get(ids=[memory_id], include=["documents"])
            return json.loads(result["documents"][0]) if result.get("documents") else None
        if operation == "delete":
            self.collection.delete(ids=[memory_id])
            return True
        raise ValueError(f"unsupported Chroma operation: {operation}")


class FaissBackend(ApplicationManagedBackend):
    def __init__(self, index_path: str, dimensions: int = 32) -> None:
        module = _required_module("faiss", "faiss-cpu")
        self.module, self.index_path, self.dimensions = module, index_path, dimensions
        self.index = module.read_index(index_path) if Path(index_path).exists() else module.IndexFlatL2(dimensions)
        self.records: dict[int, Any] = {}

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            self.index.add(__import__("numpy").array([AgentDB._embedding(request.data)], dtype="float32"))
            self.records[self.index.ntotal - 1] = request.data
            self.module.write_index(self.index, self.index_path)
            return None
        if operation in {"read", "search"}:
            return next(iter(self.records.values()), None)
        if operation == "delete":
            return True
        raise ValueError(f"unsupported FAISS operation: {operation}")


class SQLBackend(ApplicationManagedBackend):
    def __init__(self, url: str, table: str = "agent_memory") -> None:
        sqlalchemy = _required_module("sqlalchemy")
        self.engine = sqlalchemy.create_engine(url, pool_pre_ping=True, future=True)
        self.table = table
        with self.engine.begin() as connection:
            connection.exec_driver_sql(f"CREATE TABLE IF NOT EXISTS {table} (memory_id VARCHAR(255) PRIMARY KEY, agent_id VARCHAR(255) NOT NULL, payload TEXT NOT NULL, updated_at VARCHAR(64) NOT NULL)")

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        text = _required_module("sqlalchemy").text
        if operation in {"write", "update"}:
            with self.engine.begin() as connection:
                connection.execute(text(f"MERGE INTO {self.table} (memory_id, agent_id, payload, updated_at) KEY(memory_id) VALUES (:id, :agent, :payload, :updated)"), {"id": memory_id, "agent": request.agent_id, "payload": request.data, "updated": datetime.now(timezone.utc).isoformat()})
            return None
        if operation in {"read", "search"}:
            with self.engine.connect() as connection:
                row = connection.execute(text(f"SELECT payload FROM {self.table} WHERE memory_id=:id AND agent_id=:agent"), {"id": memory_id, "agent": request.agent_id}).first()
            return row[0] if row else None
        if operation == "delete":
            with self.engine.begin() as connection:
                result = connection.execute(text(f"DELETE FROM {self.table} WHERE memory_id=:id AND agent_id=:agent"), {"id": memory_id, "agent": request.agent_id})
            return result.rowcount > 0
        raise ValueError(f"unsupported SQL operation: {operation}")


class CouchDBBackend(ApplicationManagedBackend):
    def __init__(self, database: str, url: str, username: str, password: str) -> None:
        module = _required_module("couchdb")
        self.database = module.Server(url, auth=(username, password))[database]

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            self.database.save({"_id": memory_id, "agent_id": request.agent_id, "payload": request.data})
            return None
        if operation in {"read", "search"}:
            return self.database.get(memory_id, {}).get("payload")
        if operation == "delete":
            document = self.database.get(memory_id)
            if document:
                self.database.delete(document)
            return bool(document)
        raise ValueError(f"unsupported CouchDB operation: {operation}")


class FirestoreBackend(ApplicationManagedBackend):
    def __init__(self, collection: str) -> None:
        firestore = _required_module("google.cloud.firestore")
        self.document = firestore.Client().collection(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        document = self.document.document(memory_id)
        if operation in {"write", "update"}:
            document.set({"agent_id": request.agent_id, "payload": request.data})
            return None
        if operation in {"read", "search"}:
            snapshot = document.get()
            return snapshot.to_dict().get("payload") if snapshot.exists else None
        if operation == "delete":
            document.delete()
            return True
        raise ValueError(f"unsupported Firestore operation: {operation}")


class ValkeyBackend(RedisBackend):
    pass


class MemcachedBackend(ApplicationManagedBackend):
    def __init__(self, host: str, port: int = 11211) -> None:
        module = _required_module("pymemcache.client")
        self.client = module.base.Client((host, port), connect_timeout=10, timeout=10)
        self.client.version()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            self.client.set(memory_id, _json_payload(request).encode())
            return None
        if operation in {"read", "search"}:
            value = self.client.get(memory_id)
            return json.loads(value.decode()) if value else None
        if operation == "delete":
            return bool(self.client.delete(memory_id))
        raise ValueError(f"unsupported Memcached operation: {operation}")


class Neo4jBackend(ApplicationManagedBackend):
    def __init__(self, uri: str, username: str, password: str) -> None:
        module = _required_module("neo4j")
        self.driver = module.GraphDatabase.driver(uri, auth=(username, password), connection_timeout=10)
        self.driver.verify_connectivity()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        with self.driver.session() as session:
            if operation in {"write", "update"}:
                session.run("MERGE (m:Memory {id: $id}) SET m.agent_id=$agent, m.payload=$payload", id=memory_id, agent=request.agent_id, payload=request.data).consume()
                return None
            if operation in {"read", "search"}:
                record = session.run("MATCH (m:Memory {id: $id, agent_id: $agent}) RETURN m.payload AS payload", id=memory_id, agent=request.agent_id).single()
                return record["payload"] if record else None
            if operation == "delete":
                session.run("MATCH (m:Memory {id: $id, agent_id: $agent}) DETACH DELETE m", id=memory_id, agent=request.agent_id).consume()
                return True
        raise ValueError(f"unsupported Neo4j operation: {operation}")


class NeptuneBackend(Neo4jBackend):
    pass


class ArangoBackend(ApplicationManagedBackend):
    def __init__(self, url: str, database: str, username: str, password: str, collection: str = "memory") -> None:
        module = _required_module("arango")
        self.collection = module.ArangoClient(hosts=url).db(database, username=username, password=password).collection(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            self.collection.insert({"_key": memory_id, "agent_id": request.agent_id, "payload": request.data}, overwrite=True)
            return None
        if operation in {"read", "search"}:
            item = self.collection.get(memory_id)
            return item.get("payload") if item else None
        if operation == "delete":
            self.collection.delete(memory_id, ignore_missing=True)
            return True
        raise ValueError(f"unsupported ArangoDB operation: {operation}")


class TigerGraphBackend(ApplicationManagedBackend):
    def __init__(self, host: str, username: str, password: str, graph: str) -> None:
        module = _required_module("pyTigerGraph")
        self.client = module.TigerGraphConnection(host=host, username=username, password=password, graphname=graph)
        self.client.gsql("INTERPRET QUERY () FOR GRAPH %s { PRINT 1; }" % graph)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        raise SDKUnavailable("TigerGraph memory operations require an application-defined graph schema")


class LangGraphBackend(ApplicationManagedBackend):
    def __init__(self, graph: Any) -> None:
        if graph is None or not hasattr(graph, "invoke"):
            raise ValueError("an application-owned compiled LangGraph is required")
        self.graph = graph

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        return self.graph.invoke({"operation": operation, "memory_id": memory_id, "payload": request.data, "agent_id": request.agent_id})


class SolrBackend(ApplicationManagedBackend):
    def __init__(self, url: str, core: str) -> None:
        module = _required_module("pysolr")
        self.client = module.Solr(f"{url.rstrip('/')}/{core}", timeout=10)
        self.client.ping()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            self.client.add([{"id": memory_id, "agent_id_s": request.agent_id, "payload_s": json.dumps(request.data)}], commit=True)
            return None
        if operation in {"read", "search"}:
            results = self.client.search(f'id:"{memory_id}" AND agent_id_s:"{request.agent_id}"', rows=1)
            return json.loads(results.docs[0]["payload_s"]) if results.docs else None
        if operation == "delete":
            self.client.delete(id=memory_id, commit=True)
            return True
        raise ValueError(f"unsupported Solr operation: {operation}")


class OpenSearchBackend(ElasticsearchBackend):
    def __init__(self, index: str, url: str, api_key: str | None = None) -> None:
        try:
            module = importlib.import_module("opensearchpy")
        except ImportError as error:
            raise SDKUnavailable("install opensearch-py for OpenSearchBackend") from error
        self.index = index
        self._client = module.OpenSearch(hosts=[url], http_auth=(api_key, "") if api_key else None, timeout=10)
        if not self._client.ping():
            raise SDKUnavailable("OpenSearch endpoint is unavailable")


class GCSBackend(ApplicationManagedBackend):
    def __init__(self, bucket: str, prefix: str = "memory") -> None:
        storage = _required_module("google.cloud.storage")
        self.bucket = storage.Client().bucket(bucket)
        self.prefix = prefix.strip("/")

    def _blob(self, memory_id: str):
        return self.bucket.blob(f"{self.prefix}/{memory_id}.json")

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        blob = self._blob(memory_id)
        if operation in {"write", "update"}:
            blob.upload_from_string(_json_payload(request), content_type="application/json")
            return None
        if operation in {"read", "search"}:
            try:
                return json.loads(blob.download_as_text())
            except Exception:
                return None
        if operation == "delete":
            blob.delete()
            return True
        raise ValueError(f"unsupported GCS operation: {operation}")


class AzureBlobBackend(ApplicationManagedBackend):
    def __init__(self, account_url: str, container: str, credential: str) -> None:
        module = _required_module("azure.storage.blob")
        self.container = module.BlobServiceClient(account_url=account_url, credential=credential).get_container_client(container)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        blob = self.container.get_blob_client(f"{memory_id}.json")
        if operation in {"write", "update"}:
            blob.upload_blob(_json_payload(request).encode(), overwrite=True)
            return None
        if operation in {"read", "search"}:
            try:
                return json.loads(blob.download_blob().readall().decode())
            except Exception:
                return None
        if operation == "delete":
            blob.delete_blob(delete_snapshots="include")
            return True
        raise ValueError(f"unsupported Azure Blob operation: {operation}")


class FileBackend(ApplicationManagedBackend):
    def __init__(self, path: str | Path, format_name: str) -> None:
        self.path, self.format_name = Path(path), format_name
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        if operation in {"write", "update"}:
            data = request.data
            if self.format_name == "json": text = json.dumps(data, ensure_ascii=False)
            elif self.format_name == "yaml": text = _required_module("yaml").safe_dump(data)
            elif self.format_name == "csv":
                import csv, io
                output = io.StringIO(); csv.writer(output).writerows(data if isinstance(data, list) else [data]); text = output.getvalue()
            else: text = str(data)
            self.path.write_text(text, encoding="utf-8")
            return None
        if operation in {"read", "search"}:
            text = self.path.read_text(encoding="utf-8")
            if self.format_name == "json": return json.loads(text)
            if self.format_name == "yaml": return _required_module("yaml").safe_load(text)
            return text
        if operation == "delete":
            self.path.unlink(missing_ok=True)
            return True
        raise ValueError(f"unsupported file operation: {operation}")


@dataclass(frozen=True)
class OperationReceipt:
    """Safe result returned to the caller; guard decisions stay internal."""

    operation_id: str
    completed: bool
    data: Any = None


class PayloadCipher:
    """Fernet encryption boundary for memory payloads."""

    def __init__(self, key: str | bytes | None = None) -> None:
        try:
            Fernet = importlib.import_module("cryptography.fernet").Fernet
        except ImportError as error:
            raise RuntimeError("cryptography is required for encrypted memory") from error
        configured = key or os.environ.get("MEMORY_GUARD_KEY")
        if not configured:
            raise RuntimeError("MEMORY_GUARD_KEY must be configured before storage access")
        self._fernet = Fernet(configured.encode() if isinstance(configured, str) else configured)

    def encrypt(self, value: Any) -> str:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        return self._fernet.encrypt(encoded).decode()

    def decrypt(self, token: str) -> Any:
        return json.loads(self._fernet.decrypt(token.encode()).decode())


class DatabaseManager:
    """SQLite repository for agent records and guard decisions."""

    def __init__(self, database_path: str | Path = "memory_guard.db", encryption_key: str | bytes | None = None) -> None:
        self.database_path = str(database_path)
        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self.cipher = PayloadCipher(encryption_key)
        self.create_tables(agent=True, guard=True)

    def close(self) -> None:
        self.connection.close()

    def create_tables(self, agent: bool = False, guard: bool = False) -> bool:
        with self.connection:
            if agent:
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY, agent_name TEXT NOT NULL,
                        agent_version TEXT NOT NULL, agent_author TEXT NOT NULL,
                        agent_description TEXT NOT NULL, session_id TEXT NOT NULL,
                        request_id TEXT NOT NULL, operation TEXT NOT NULL,
                        store TEXT NOT NULL, permissions TEXT NOT NULL,
                        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    )
                    """
                )
            if guard:
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS guard_actions (
                        action_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
                        action TEXT NOT NULL, decision TEXT NOT NULL,
                        reasons TEXT NOT NULL, risk_score REAL NOT NULL,
                        confidence REAL NOT NULL, timestamp TEXT NOT NULL
                    )
                    """
                )
        return True

    def insert_data(self, table_name: str, data: dict[str, Any]) -> dict[str, Any]:
        table = self._normalize_table(table_name)
        if not data:
            raise ValueError("data cannot be empty")
        allowed = self._table_columns(table)
        values = {key: value for key, value in data.items() if key in allowed}
        missing = self._required_columns(table) - values.keys()
        if missing:
            raise ValueError(f"Missing required fields for {table}: {sorted(missing)}")
        columns = list(values)
        placeholders = ", ".join("?" for _ in columns)
        with self.connection:
            self.connection.execute(
                f"INSERT OR REPLACE INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
                tuple(self._serialize(value) for value in values.values()),
            )
        return data

    def query_data(self, table_name: str, record_id: str) -> Optional[dict[str, Any]]:
        table = self._normalize_table(table_name)
        key = "agent_id" if table == "agents" else "action_id"
        row = self.connection.execute(
            f"SELECT * FROM {table} WHERE {key} = ?", (str(record_id),)
        ).fetchone()
        return dict(row) if row else None

    def delete_data(self, table_name: str, record_id: str) -> bool:
        table = self._normalize_table(table_name)
        key = "agent_id" if table == "agents" else "action_id"
        with self.connection:
            cursor = self.connection.execute(
                f"DELETE FROM {table} WHERE {key} = ?", (str(record_id),)
            )
        return cursor.rowcount > 0

    def _normalize_table(self, table_name: str) -> str:
        if table_name.lower() not in {"agent", "guard"}:
            raise ValueError("table_name must be Agent or Guard")
        return "agentsOperations" if table_name.lower() == "agent" else "guard_actions"

    def _table_columns(self, table: str) -> set[str]:
        return {row[1] for row in self.connection.execute(f"PRAGMA table_info({table})")}

    def _required_columns(self, table: str) -> set[str]:
        return {row[1] for row in self.connection.execute(f"PRAGMA table_info({table})") if row[3] and row[5] == 0}

    @staticmethod
    def _serialize(value: Any) -> Any:
        return json.dumps(value) if isinstance(value, (list, tuple, dict)) else value


class AgentDB:
    """Authorize and persist memory operations for one agent request."""

    def __init__(self, request: Optional[AgentRequest] = None, reasons: str = "", dbmanager: Optional[DatabaseManager] = None, provider: str = "generic", cyber_ai: Optional[CyberAI] = None, backend: Optional[ApplicationManagedBackend] = None) -> None:
        self.request = request
        self.reasons = reasons
        self.dbmanager = dbmanager or DatabaseManager()
        self.provider = provider
        self.cyber_ai = cyber_ai
        self.backend = backend

    def _metadata(self) -> dict[str, Any]:
        if self.request is None:
            return {}
        return {field: getattr(self.request, field) for field in (
            "agent_id", "agent_name", "agent_version", "agent_author",
            "agent_description", "session_id", "request_id", "operation", "store"
        )} | {"permissions": list(self.request.permissions)}

    def _authorize(self, operation: str) -> GuardDecision:
        if self.request is None:
            return GuardDecision(Decision.QUARANTINE, 1.0, ("missing_request",), "pre")
        metadata = self._metadata()
        payload = self.request.data if self.request.data is not None else metadata
        guard = MemoryGuard(
            action=operation,
            source={"data": payload, "metadata": metadata},
            infos=metadata,
            cyber_ai=self.cyber_ai,
        )
        return guard.evaluate()

    def _agent_record(self) -> dict[str, Any]:
        if self.request is None:
            raise ValueError("An AgentRequest is required for this operation")
        now = datetime.now(timezone.utc).isoformat()
        return {**self._metadata(), "created_at": now, "updated_at": now}

    def read(self, id: Optional[str] = None) -> OperationReceipt:
        return self._run("read", id)

    def write(self, id: Optional[str] = None) -> OperationReceipt:
        return self._run("write", id, persist=True)

    def update(self, id: Optional[str] = None) -> OperationReceipt:
        return self._run("update", id, persist=True)

    def delete(self, id: Optional[str] = None) -> OperationReceipt:
        return self._run("delete", id, remove=True)

    def _run(self, operation: str, id: Optional[str], persist: bool = False, remove: bool = False) -> OperationReceipt:
        operation_id = str(uuid.uuid4())
        decision = self._authorize(operation)
        if decision.decision is not Decision.ALLOW:
            return OperationReceipt(operation_id, False)
        record_id = id or (self.request.agent_id if self.request else None)
        if not record_id:
            return OperationReceipt(operation_id, False)
        memory_id = self.request.memory_id or record_id
        if self.backend is not None:
            encrypted_request = replace(
                self.request,
                data=self.dbmanager.cipher.encrypt(self.request.data),
            )
            result = self.backend.execute(operation, encrypted_request, memory_id)
            if result is not None and operation in {"read", "search"}:
                try:
                    result = self.dbmanager.cipher.decrypt(result)
                except (TypeError, ValueError):
                    pass
        else:
            return OperationReceipt(operation_id, False)
        self._record_guard_action(operation, decision)
        return OperationReceipt(operation_id, True, result)

    @staticmethod
    def _embedding(value: Any, dimensions: int = 32) -> list[float]:
        """Deterministic local embedding fallback; replaceable by a model adapter."""
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
        digest = hashlib.sha256(raw).digest()
        return [((digest[index % len(digest)] / 255.0) * 2.0) - 1.0 for index in range(dimensions)]

    def _record_guard_action(self, operation: str, decision: GuardDecision) -> None:
        if self.request is None:
            return
        self.dbmanager.insert_data("Guard", {
            "action_id": str(uuid.uuid4()), "agent_id": self.request.agent_id,
            "action": operation, "decision": decision.decision.value, "reasons": ",".join(decision.reason_codes) or self.reasons,
            "risk_score": decision.risk_score,
            "confidence": 1.0, "timestamp": datetime.now(timezone.utc).isoformat(),
        })


class MemoryAdapterInterface(ABC):
    """Common CRUD contract for every memory backend adapter."""

    @abstractmethod
    def read(self, request: AgentRequest, reasons: str = "") -> str: ...

    @abstractmethod
    def write(self, request: AgentRequest, reasons: str = "") -> str: ...

    @abstractmethod
    def update(self, request: AgentRequest, reasons: str = "") -> str: ...

    @abstractmethod
    def delete(self, request: AgentRequest, reasons: str = "") -> str: ...


class MemoryAdapterMixin:
    backend_name = "generic"
    backend_kind = "memory"
    capabilities = frozenset({"read", "write", "update", "delete"})

    def __init__(self, dbmanager: Optional[DatabaseManager] = None, **backend_config: Any) -> None:
        self.auth = "quarantine"
        self.backend_config = dict(backend_config)
        encryption_key = self.backend_config.pop("encryption_key", None)
        self.cyber_ai = self.backend_config.pop("cyber_ai", None)
        self.backend = self.backend_config.pop("backend", None)
        managed_db = dbmanager or DatabaseManager(encryption_key=encryption_key)
        self.agent_db = AgentDB(dbmanager=managed_db, cyber_ai=self.cyber_ai, backend=self.backend)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.backend_config.get("provider", self.backend_name),
            "kind": self.backend_kind,
            "capabilities": sorted(self.capabilities),
            "configuration": {
                key: value for key, value in self.backend_config.items()
                if key not in {"api_key", "access_key", "secret_key", "password", "token", "encryption_key"}
            },
        }

    def _dispatch(self, request: AgentRequest, reasons: str, operation: str) -> OperationReceipt:
        if request is None:
            raise ValueError("request is required")
        provider = self.backend_config.get("provider", "generic")
        self.agent_db = AgentDB(
            request=request,
            reasons=reasons,
            dbmanager=self.agent_db.dbmanager,
            provider=provider,
            cyber_ai=self.cyber_ai,
            backend=self.backend,
        )
        receipt = getattr(self.agent_db, operation)(id=request.agent_id)
        self.auth = "completed" if receipt.completed else "rejected"
        return receipt


class CRUDAdapter(MemoryAdapterInterface, MemoryAdapterMixin):
    def __init__(self, dbmanager: Optional[DatabaseManager] = None, **backend_config: Any) -> None:
        MemoryAdapterMixin.__init__(self, dbmanager, **backend_config)

    def read(self, request: AgentRequest, reasons: str = "") -> str:
        return self._dispatch(request, reasons, "read")

    def write(self, request: AgentRequest, reasons: str = "") -> str:
        return self._dispatch(request, reasons, "write")

    def update(self, request: AgentRequest, reasons: str = "") -> str:
        return self._dispatch(request, reasons, "update")

    def delete(self, request: AgentRequest, reasons: str = "") -> str:
        return self._dispatch(request, reasons, "delete")


class VectorAdapter(CRUDAdapter):
    backend_kind = "vector"

    def search(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def insert(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class RelationalAdapter(CRUDAdapter):
    backend_kind = "relational"

    execute_read = CRUDAdapter.read
    execute_write = CRUDAdapter.write
    execute_update = CRUDAdapter.update
    execute_delete = CRUDAdapter.delete


class DocumentMemoryAdapter(CRUDAdapter):
    backend_kind = "document"

    def find_doc(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def insert_doc(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class KeyValueMemoryAdapter(CRUDAdapter):
    backend_kind = "key_value"

    def get_val(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def set_val(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class GraphAdapter(CRUDAdapter):
    backend_kind = "graph"

    def query(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def create_nodeAndedge(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class SearchEngineAdapter(CRUDAdapter):
    backend_kind = "search"

    def search_index(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def index(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class ObjectStorageAdapter(CRUDAdapter):
    backend_kind = "object_storage"

    def get_obj(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def put_obj(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class FileSysAdapter(CRUDAdapter):
    backend_kind = "file"

    def read_file(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def write_file(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class QDRANT(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("qdrant", config)
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="qdrant", collection=collection, backend=QdrantBackend(collection, config.pop("url", None), config.pop("api_key", None)), **config)

class PINECONE(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("pinecone", config)
        index = config.pop("index", "memory")
        super().__init__(dbmanager, provider="pinecone", index=index, backend=PineconeBackend(index, config.pop("namespace", "default"), config.pop("api_key", None)), **config)

class WEAVIATE(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("weaviate", config)
        collection = config.pop("class_name", "Memory")
        super().__init__(dbmanager, provider="weaviate", class_name=collection, backend=WeaviateBackend(collection, config.pop("url", os.environ.get("WEAVIATE_URL")), config.pop("api_key", os.environ.get("WEAVIATE_API_KEY"))), **config)

class MILVUS(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("milvus", config)
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="milvus", collection=collection, backend=MilvusBackend(collection, config.pop("uri", os.environ.get("MILVUS_URL")), config.pop("token", os.environ.get("MILVUS_TOKEN"))), **config)

class CHROMA(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("chroma", config)
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="chroma", collection=collection, backend=ChromaBackend(collection, config.pop("host", os.environ.get("CHROMA_HOST")), int(config.pop("port", os.environ.get("CHROMA_PORT", "8000")))), **config)

class FAISS(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        index_path = config.pop("index_path", "memory.index")
        super().__init__(dbmanager, provider="faiss", index_path=index_path, backend=FaissBackend(index_path, int(config.pop("dimensions", 32))), **config)

class PGVECTOR(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="pgvector", table=config.pop("table", "memory"), **config)

class VESPA(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="vespa", schema=config.pop("schema", "memory"), **config)

class POSTGRESQL(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("postgresql", config)
        super().__init__(dbmanager, provider="postgresql", schema=config.pop("schema", "public"), backend=SQLBackend(config.pop("url", os.environ.get("POSTGRESQL_URL")), config.pop("table", "agent_memory")), **config)

class ORACLE(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("oracle", config)
        super().__init__(dbmanager, provider="oracle", schema=config.pop("schema", "MEMORY"), backend=SQLBackend(config.pop("url", os.environ.get("ORACLE_URL")), config.pop("table", "agent_memory")), **config)

class SQLITE(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        database_path = config.pop("database_path", "agent_memory.db")
        super().__init__(dbmanager, provider="sqlite", table=config.pop("table", "memory"), backend=SQLiteBackend(database_path), **config)

class SQLSERVER(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("sqlserver", config)
        super().__init__(dbmanager, provider="sqlserver", schema=config.pop("schema", "dbo"), backend=SQLBackend(config.pop("url", os.environ.get("SQLSERVER_URL")), config.pop("table", "agent_memory")), **config)

class MARIADB(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("mariadb", config)
        super().__init__(dbmanager, provider="mariadb", table=config.pop("table", "memory"), backend=SQLBackend(config.pop("url", os.environ.get("MARIADB_URL")), config.pop("table", "agent_memory")), **config)

class MONGODB(DocumentMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("mongodb", config)
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="mongodb", collection=collection, backend=MongoBackend(config.pop("database", "memory"), collection, config.pop("uri", None)), **config)

class COUCHDB(DocumentMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("couchdb", config)
        database = config.pop("database", "memory")
        super().__init__(dbmanager, provider="couchdb", database=database, backend=CouchDBBackend(database, config.pop("url", os.environ.get("COUCHDB_URL")), config.pop("username", os.environ.get("COUCHDB_USERNAME")), config.pop("password", os.environ.get("COUCHDB_PASSWORD"))), **config)

class FIRESTORE(DocumentMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="firestore", collection=collection, backend=FirestoreBackend(collection), **config)

class DYNAMODB(DocumentMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("dynamodb", config)
        table = config.pop("table", "memory")
        super().__init__(dbmanager, provider="dynamodb", table=table, backend=DynamoDBBackend(table, config.pop("region", None)), **config)

class REDIS(KeyValueMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("redis", config)
        namespace = config.pop("namespace", "memory")
        super().__init__(dbmanager, provider="redis", namespace=namespace, backend=RedisBackend(namespace, config.pop("url", None)), **config)

class VALKEY(KeyValueMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        namespace = config.pop("namespace", "memory")
        super().__init__(dbmanager, provider="valkey", namespace=namespace, backend=ValkeyBackend(namespace, config.pop("url", os.environ.get("VALKEY_URL"))), **config)

class MEMECACHED(KeyValueMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="memcached", namespace=config.pop("namespace", "memory"), backend=MemcachedBackend(config.pop("host", os.environ.get("MEMCACHED_HOST")), int(config.pop("port", os.environ.get("MEMCACHED_PORT", "11211")))), **config)

class NEO4J(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="neo4j", graph=config.pop("graph", "memory"), backend=Neo4jBackend(config.pop("url", os.environ.get("NEO4J_URI")), config.pop("username", os.environ.get("NEO4J_USERNAME")), config.pop("password", os.environ.get("NEO4J_PASSWORD"))), **config)

class AMAZONE_NEPTURE(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="amazon_neptune", graph=config.pop("graph", "memory"), backend=NeptuneBackend(config.pop("url", os.environ.get("NEPTUNE_URI")), config.pop("username", os.environ.get("NEPTUNE_USERNAME")), config.pop("password", os.environ.get("NEPTUNE_PASSWORD"))), **config)

class ARANGO_DB(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="arangodb", graph=config.pop("graph", "memory"), backend=ArangoBackend(config.pop("url", os.environ.get("ARANGO_URL")), config.pop("database", "memory"), config.pop("username", os.environ.get("ARANGO_USERNAME")), config.pop("password", os.environ.get("ARANGO_PASSWORD"))), **config)

class TIGER_GRAPH(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="tigergraph", graph=config.pop("graph", "memory"), backend=TigerGraphBackend(config.pop("url", os.environ.get("TIGERGRAPH_URL")), config.pop("username", os.environ.get("TIGERGRAPH_USERNAME")), config.pop("password", os.environ.get("TIGERGRAPH_PASSWORD")), config.pop("graph", "memory")), **config)

class LANGRAPH(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="langgraph", graph=config.pop("graph", "memory"), backend=LangGraphBackend(config.pop("graph_app", None)), **config)

class SOLR(SearchEngineAdapter):
    def __init__(self, dbmanager=None, **config):
        core = config.pop("core", "memory")
        super().__init__(dbmanager, provider="solr", core=core, backend=SolrBackend(config.pop("url", os.environ.get("SOLR_URL")), core), **config)

class OPENSEARCH(SearchEngineAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("opensearch", config)
        index = config.pop("index", "memory")
        super().__init__(dbmanager, provider="opensearch", index=index, backend=OpenSearchBackend(index, config.pop("url", os.environ.get("OPENSEARCH_URL")), config.pop("api_key", os.environ.get("OPENSEARCH_API_KEY"))), **config)

class ELASTICSEARCH(SearchEngineAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("elasticsearch", config)
        index = config.pop("index", "memory")
        super().__init__(dbmanager, provider="elasticsearch", index=index, backend=ElasticsearchBackend(index, config.pop("url", None), config.pop("api_key", None)), **config)

class AMAZON_S3(ObjectStorageAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("amazon_s3", config)
        bucket = config.pop("bucket", "memory")
        super().__init__(dbmanager, provider="amazon_s3", bucket=bucket, backend=S3Backend(bucket, config.pop("prefix", "memory"), config.pop("region", None)), **config)

class GOOGLE_CLOUD_STORAGE(ObjectStorageAdapter):
    def __init__(self, dbmanager=None, **config):
        bucket = config.pop("bucket", "memory")
        super().__init__(dbmanager, provider="google_cloud_storage", bucket=bucket, backend=GCSBackend(bucket, config.pop("prefix", "memory")), **config)

class AZURE_BLOB_STORAGE(ObjectStorageAdapter):
    def __init__(self, dbmanager=None, **config):
        container = config.pop("container", "memory")
        super().__init__(dbmanager, provider="azure_blob_storage", container=container, backend=AzureBlobBackend(config.pop("account_url", os.environ.get("AZURE_STORAGE_ACCOUNT_URL")), container, config.pop("credential", os.environ.get("AZURE_STORAGE_CREDENTIAL"))), **config)

class JSON(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory.json")
        super().__init__(dbmanager, provider="json", path=path, backend=FileBackend(path, "json"), **config)

class YAML(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory.yaml")
        super().__init__(dbmanager, provider="yaml", path=path, backend=FileBackend(path, "yaml"), **config)

class CSV(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory.csv")
        super().__init__(dbmanager, provider="csv", path=path, backend=FileBackend(path, "csv"), **config)

class TXT(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory.txt")
        super().__init__(dbmanager, provider="txt", path=path, backend=FileBackend(path, "txt"), **config)

class LOCALFILES(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", ".")
        super().__init__(dbmanager, provider="local_files", path=path, backend=FileBackend(path, "txt"), **config)


class StoreRegistry:
    """Application-owned mapping from logical stores to hidden adapters."""

    def __init__(self) -> None:
        self._stores: dict[str, StoreConfig] = {}

    def register(self, config: StoreConfig) -> None:
        if config.store_id in self._stores:
            raise ValueError(f"store already registered: {config.store_id}")
        self._stores[config.store_id] = config

    def resolve(self, store_id: str) -> StoreConfig:
        try:
            return self._stores[store_id]
        except KeyError as error:
            raise PermissionError("unknown memory store") from error

    def list_store_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._stores))


class AuditLog:
    """Append-only in-process audit sink; agents receive no mutable log handle."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)

    def snapshot(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)


class QuarantineStore:
    """Private holding area for suspicious data; never exposed through agent results."""

    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}

    def put(self, request_id: str, payload: Any, reason_codes: tuple[str, ...]) -> str:
        quarantine_id = str(uuid.uuid4())
        self._items[quarantine_id] = {
            "request_id": request_id,
            "payload": payload,
            "reason_codes": tuple(reason_codes),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return quarantine_id

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self._items.values())


@dataclass(frozen=True)
class AccessResult:
    request_id: str
    decision: Decision
    data: Any = None
    reason_codes: tuple[str, ...] = ()
    operation_id: str | None = None
