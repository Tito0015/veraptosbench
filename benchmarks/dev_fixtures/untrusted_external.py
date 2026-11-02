import requests


def fetch(url, state):
    # semgrep-sink
    response = requests.get(url)
    state["body"] = response.text
    return state


def pure(state):
    # semgrep-ok
    return len(state)
