#!/usr/bin/env bash
set -o errexit
pip install -r requirements.txt
gunicorn app:app
