#!/usr/bin/env python3
import os
import json
from pathlib import Path
import click
import httpx

BASE_URL = os.getenv("SENTINEL_URL", "http://localhost:8000")
TOKEN_FILE = Path.home() / ".sentinel_token"


def _save_token(token: str):
    TOKEN_FILE.write_text(token)


def _load_token() -> str:
    if not TOKEN_FILE.exists():
        raise click.ClickException("Not logged in. Run: sentinel login <username> <password>")
    return TOKEN_FILE.read_text().strip()


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {_load_token()}"}


@click.group()
def cli():
    """Sentinel CLI — secrets management"""
    pass


@cli.command()
@click.argument("username")
@click.argument("password")
def register(username, password):
    r = httpx.post(f"{BASE_URL}/auth/register", json={"username": username, "password": password})
    r.raise_for_status()
    _save_token(r.json()["access_token"])
    click.echo(f"Registered and logged in as {username}")


@cli.command()
@click.argument("username")
@click.argument("password")
def login(username, password):
    r = httpx.post(f"{BASE_URL}/auth/login", json={"username": username, "password": password})
    r.raise_for_status()
    _save_token(r.json()["access_token"])
    click.echo(f"Logged in as {username}")


@cli.command("set")
@click.argument("key")
@click.argument("value")
def set_secret(key, value):
    headers = _auth_headers()
    r = httpx.put(f"{BASE_URL}/secrets/{key}", headers=headers, json={"value": value})
    if r.status_code == 404:
        r = httpx.post(f"{BASE_URL}/secrets", headers=headers, json={"key": key, "value": value})
    r.raise_for_status()
    click.echo(f"Secret '{key}' saved.")


@cli.command("get")
@click.argument("key")
def get_secret(key):
    r = httpx.get(f"{BASE_URL}/secrets/{key}", headers=_auth_headers())
    r.raise_for_status()
    click.echo(r.json()["value"])


@cli.command("delete")
@click.argument("key")
def delete_secret(key):
    r = httpx.delete(f"{BASE_URL}/secrets/{key}", headers=_auth_headers())
    r.raise_for_status()
    click.echo(f"Secret '{key}' deleted.")


if __name__ == "__main__":
    cli()
