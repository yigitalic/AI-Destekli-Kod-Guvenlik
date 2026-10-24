"""Örnek zafiyetli Python servisi (AI-SAST FAZ 3 Doğrulama Demosu).

Bu dosya, Layer 2 AST ve Sezgisel kural motorlarının tespit yeteneklerini
göstermek amacıyla hazırlanmış bilerek zafiyetli kod parçacıkları içerir.
"""

import hashlib
import os
import pickle
import requests
import sqlite3
import yaml

# Layer 1 tarafından yakalanacak ve Layer 2 Context Window'da maskelenecek gizli anahtar
OPENAI_API_KEY = "sk-proj-999988887777666655554444333322221111"


def login_handler(username: str, password: str):
    # AST_SQLI_01: Dinamik f-string SQL enjeksiyonu
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    # AST_CRYPTO_01: Zayıf kriptografik özet (MD5)
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    return user


def backup_service(backup_param: str):
    # AST_CMD_01: Güvensiz kabuk komutu çalıştırma
    os.system("tar -czf backup.tar.gz " + backup_param)


def session_deserializer(raw_data: bytes):
    # AST_DESER_01: Güvensiz pickle deserialization
    return pickle.loads(raw_data)


def parse_user_config(raw_yaml: str):
    # AST_DESER_01: SafeLoader olmadan yaml.load
    return yaml.load(raw_yaml)


def fetch_internal_metrics(service_url: str):
    # AST_TLS_01: Devre dışı bırakılmış SSL doğrulaması
    return requests.get(service_url, verify=False, timeout=5)


def calculate_formula(expr: str):
    # AST_EXEC_01: Dinamik eval çalıştırması
    return eval(expr)
