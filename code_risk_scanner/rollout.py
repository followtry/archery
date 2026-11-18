# -*- coding: utf-8 -*-
"""交易团队应用的四轮试点。名单来自 stability_ai 的 data/apps.json，这里只做筛选。"""

import fnmatch
import json
import os

APPS_URL = "https://code.alibaba-inc.com/AOS-TMP/stability_ai/blob/master/data/apps.json"

ROUNDS = {
    1: {
        "title": "第一轮：逆向团队里名字匹配 kernel* 的服务",
        "teams": ["逆向"],
        "glob": "kernel*",
    },
    2: {
        "title": "第二轮：逆向团队全部应用",
        "teams": ["逆向"],
        "glob": "*",
    },
    3: {
        "title": "第三轮：正向和支付履约团队全部应用",
        "teams": ["正向", "支付履约"],
        "glob": "*",
    },
    4: {
        "title": "第四轮：交易团队全部应用",
        "teams": ["逆向", "正向", "支付履约"],
        "glob": "*",
    },
}


def load_apps(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    apps = _normalize(data)
    if not apps:
        raise ValueError("{0} 里没有识别出应用。名单格式见规则说明，来源是 {1}".format(path, APPS_URL))
    return apps


def select_round(apps, round_no):
    if round_no not in ROUNDS:
        raise ValueError("轮次只能是 1、2、3、4")
    spec = ROUNDS[round_no]
    chosen = []
    for app in apps:
        if app["team"] not in spec["teams"]:
            continue
        if not fnmatch.fnmatch(app["name"].lower(), spec["glob"]):
            continue
        chosen.append(app)
    chosen.sort(key=lambda item: (item["team"], item["name"].lower()))
    return {
        "round": round_no,
        "title": spec["title"],
        "apps_url": APPS_URL,
        "app_count": len(chosen),
        "apps": chosen,
    }


def _normalize(data):
    if isinstance(data, dict):
        for key in ("apps", "data", "applications"):
            if isinstance(data.get(key), list):
                return _from_list(data[key])
        apps = []
        for key, value in data.items():
            if key.startswith("_"):
                continue
            team = _team(key)
            if team is None:
                continue
            rows = value.get("apps") if isinstance(value, dict) else value
            if not isinstance(rows, list):
                continue
            apps.extend(_from_list(rows, team))
        return apps
    if isinstance(data, list):
        return _from_list(data)
    raise ValueError("apps.json 必须是对象或数组")


def _from_list(rows, team=None):
    apps = []
    for row in rows:
        if isinstance(row, str):
            name = row.strip()
            item_team = team
            repo = ""
        elif isinstance(row, dict):
            name = str(row.get("name") or row.get("app") or row.get("appName") or row.get("app_name") or "").strip()
            item_team = team or _team(row.get("team") or row.get("group") or row.get("org") or row.get("bizTeam") or "")
            repo = str(row.get("repo") or row.get("git") or row.get("url") or "")
        else:
            continue
        if not name or item_team is None:
            continue
        apps.append({"name": name, "team": item_team, "repo": repo})
    return apps


def _team(value):
    text = str(value).strip().lower()
    if not text:
        return None
    if "逆向" in text or text in ("reverse", "refund"):
        return "逆向"
    if "支付" in text or "履约" in text or text in ("payment", "fulfillment", "pay"):
        return "支付履约"
    if "正向" in text or text in ("forward", "buy"):
        return "正向"
    return None


def default_apps_path(repo):
    for relative in ("data/apps.json", os.path.join("stability_ai", "data", "apps.json")):
        path = os.path.join(repo, relative)
        if os.path.isfile(path):
            return path
    return ""
