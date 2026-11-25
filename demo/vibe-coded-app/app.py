"""Fictional AI-generated API used to demo the vibe-coding checks. Do not deploy."""
import sqlite3

import requests
from fastapi import FastAPI

app = FastAPI()
db = sqlite3.connect("app.db")


@app.get("/users/{user_id}")
def get_user(user_id: str):
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cur.fetchone()


@app.get("/avatar")
def avatar(url: str):
    return requests.get(url, verify=False).content
