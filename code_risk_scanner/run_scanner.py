# -*- coding: utf-8 -*-
"""代码隐患扫描入口。

周期巡检：
    python3 code_risk_scanner/run_scanner.py \\
        --repo-path "$WORKSPACE" \\
        --skill-dir code_risk_scanner \\
        --scan-mode FULL_PERIODIC \\
        --output scan_report.json

MR 门禁：把 scan-mode 换成 INCREMENTAL_MR，并传 --diff-base origin/master。
有 Critical 时退出码为 1。
"""

import argparse
import sys

if __package__ in (None, ""):
    sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from code_risk_scanner.engine import decide_exit, scan
from code_risk_scanner.report import dump_report, load_report, notify_dingtalk, render_alert, validate
from code_risk_scanner.rollout import load_apps, select_round


def main(argv=None):
    parser = argparse.ArgumentParser(description="扫描 Java/Go 代码里的中间件和并发隐患")
    parser.add_argument("--repo-path", default=".")
    parser.add_argument("--skill-dir", default="")
    parser.add_argument("--scan-mode", default="FULL_PERIODIC", choices=["FULL_PERIODIC", "INCREMENTAL_MR"])
    parser.add_argument("--output", default="scan_report.json")
    parser.add_argument("--diff-base", default="")
    parser.add_argument("--blame", action="store_true")
    parser.add_argument("--sharding-keys", default="", help="逗号分隔，覆盖默认分片键")
    parser.add_argument("--render-alert", default="", help="把已有报告转成告警正文，写到这个路径；传 - 则打到标准输出")
    parser.add_argument("--notify", default="", help="读取这份报告。webhook 只用环境变量 DINGTALK_WEBHOOK")
    parser.add_argument("--self-check", action="store_true", help="跑扫描器自己的单元测试")
    parser.add_argument("--round", type=int, choices=[1, 2, 3, 4], help="交易团队试点轮次：1 kernel* 逆向，2 逆向全部，3 正向和支付履约，4 全部")
    parser.add_argument("--apps", default="", help="data/apps.json 路径。来源是 code.alibaba-inc.com/AOS-TMP/stability_ai")
    parser.add_argument("--list-round", action="store_true", help="只打印这一轮要跑的应用，不扫描代码")
    args = parser.parse_args(argv)

    if args.self_check:
        import unittest
        suite = unittest.defaultTestLoader.discover("code_risk_scanner.tests")
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        return 0 if result.wasSuccessful() else 1
    if args.render_alert:
        text = render_alert(validate(load_report(args.render_alert if args.render_alert != "-" else args.output)))
        # --render-alert PATH 读 PATH。额外把正文打到标准输出，方便流水线重定向。
        sys.stdout.write(text)
        return 0
    if args.notify:
        report = validate(load_report(args.notify))
        webhook = __import__("os").environ.get("DINGTALK_WEBHOOK", "")
        if not webhook:
            sys.stderr.write("未设置 DINGTALK_WEBHOOK，跳过发送\n")
            return 0
        notify_dingtalk(report, webhook)
        return 0

    rollout = None
    if args.round or args.list_round:
        if not args.round or not args.apps:
            sys.stderr.write("列出或绑定试点轮次时，必须同时提供 --round 和 --apps\n")
            return 2
        rollout = select_round(load_apps(args.apps), args.round)
        if args.list_round:
            sys.stdout.write(__import__("json").dumps(rollout, ensure_ascii=False, indent=2) + "\n")
            return 0
    keys = [item.strip() for item in args.sharding_keys.split(",") if item.strip()] or None
    report = scan(
        args.repo_path,
        scan_mode=args.scan_mode,
        diff_base=args.diff_base or None,
        blame=args.blame,
        sharding_keys=keys,
        skill_dir=args.skill_dir or None,
        rollout=rollout,
    )
    validate(report)
    dump_report(report, args.output)
    summary = report["summary"]
    sys.stdout.write(
        "gate={gate} critical={critical_count} warning={warning_count} suggestion={suggestion_count} files={files} report={output}\n".format(
            gate=report["gate_status"],
            files=report["scan_metadata"]["scanned_files_count"],
            output=args.output,
            **summary,
        )
    )
    return decide_exit(args.scan_mode, report["gate_status"])


if __name__ == "__main__":
    sys.exit(main())
